//! Redis Command Builder
//!
//! Builds Redis CLI commands for remote execution via SSH.
//! Supports info, arbitrary CLI commands, and key scanning.

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

use super::shell::{is_loopback_host, refuse_option_like};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Longest `redis_host` accepted: the length limit of a DNS name.
const REDIS_HOST_MAX_LEN: usize = 253;

/// Longest `redis_password` accepted.
const REDIS_PASSWORD_MAX_LEN: usize = 1024;

/// Shell prefix of a `redis-cli` that connects to a server other than the
/// local one: drops the ambient credentials of the client (`REDISCLI_AUTH`,
/// and `VALKEYCLI_AUTH`, which `valkey-cli` reads first and which is what
/// `redis-cli` runs on distributions that ship Valkey), so that nothing of the
/// SSH host is sent to a server the caller chose. `unset` is a POSIX
/// builtin; the command runs in the SSH user's shell, so nothing outlives it.
/// It is joined with `&&`, not `;`: `unset` of a `readonly` variable fails,
/// and the client must not start then (a surviving variable would be sent to
/// the server). `unset` of a variable that is not set succeeds.
const REDIS_REMOTE_UNSET: &str = "unset REDISCLI_AUTH VALKEYCLI_AUTH && ";

/// Whether `redis_host` designates the Redis server of the SSH host itself,
/// the only one the host's `REDISCLI_AUTH` or `VALKEYCLI_AUTH` may be sent to: no host (the
/// client defaults to `127.0.0.1`), `localhost` or a loopback IP address.
/// Anything else is another server.
fn is_local_redis_host(redis_host: Option<&str>) -> bool {
    redis_host.is_none_or(is_loopback_host)
}

/// Start of every `redis-cli` command line, up to the options that precede
/// the command words.
///
/// - another server: [`REDIS_REMOTE_UNSET`] first;
/// - a password: `printf '%s\n' '<pw>' | redis-cli --askpass`, so the password
///   is never an argument of `redis-cli` (`--askpass` reads it from standard
///   input and makes the client ignore both `-a` and `REDISCLI_AUTH`);
/// - then `-h` and `-p`. `redis-cli` reads its options up to the first word
///   that is not one, so everything the caller of this function appends comes
///   after them.
fn client_prefix(
    redis_host: Option<&str>,
    redis_port: Option<u16>,
    redis_password: Option<&str>,
) -> String {
    let mut cmd = String::new();
    if !is_local_redis_host(redis_host) {
        cmd.push_str(REDIS_REMOTE_UNSET);
    }
    if let Some(pw) = redis_password {
        let _ = write!(cmd, "printf '%s\\n' {} | ", shell_escape(pw));
    }
    cmd.push_str("redis-cli");
    if redis_password.is_some() {
        cmd.push_str(" --askpass");
    }
    if let Some(h) = redis_host {
        let _ = write!(cmd, " -h {}", shell_escape(h));
    }
    if let Some(p) = redis_port {
        let _ = write!(cmd, " -p {p}");
    }
    cmd
}

/// Builds Redis CLI commands for remote execution.
pub struct RedisCommandBuilder;

impl RedisCommandBuilder {
    /// Check the connection arguments of a Redis tool.
    ///
    /// `redis_host` must not be empty (omit it for the local server) and holds
    /// one host name or address: ASCII letters, digits and `. - _ : %` only,
    /// at most 253 bytes, not starting with `-`. `redis_password` must not be
    /// empty (omit it), must not contain a line break or any other control
    /// character, and holds at most 1024 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] naming the offending argument.
    pub fn validate_connection(
        redis_host: Option<&str>,
        redis_password: Option<&str>,
    ) -> Result<()> {
        if let Some(host) = redis_host {
            if host.is_empty() {
                return Err(BridgeError::CommandDenied {
                    reason: "'redis_host' must not be empty: omit it for the local server"
                        .to_string(),
                });
            }
            refuse_option_like("redis_host", host)?;
            let name_like = host.len() <= REDIS_HOST_MAX_LEN
                && host.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'%')
                });
            if !name_like {
                return Err(BridgeError::CommandDenied {
                    reason: format!(
                        "'redis_host' must be one host name or IP address: ASCII letters, \
                         digits and . - _ : % only, at most {REDIS_HOST_MAX_LEN} bytes"
                    ),
                });
            }
        }
        if let Some(pw) = redis_password {
            if pw.is_empty() {
                return Err(BridgeError::CommandDenied {
                    reason: "'redis_password' must not be empty: omit it".to_string(),
                });
            }
            if pw.chars().any(char::is_control) {
                return Err(BridgeError::CommandDenied {
                    reason: "'redis_password' must not contain a line break or another \
                             control character: it is read as one line"
                        .to_string(),
                });
            }
            if pw.len() > REDIS_PASSWORD_MAX_LEN {
                return Err(BridgeError::CommandDenied {
                    reason: format!(
                        "'redis_password' must be at most {REDIS_PASSWORD_MAX_LEN} bytes long"
                    ),
                });
            }
        }
        Ok(())
    }

    /// Build a `redis-cli INFO` command.
    ///
    /// Constructs: `[unset REDISCLI_AUTH VALKEYCLI_AUTH && ] [printf '%s\n' {password} | ]
    /// redis-cli [--askpass] [-h {host}] [-p {port}] INFO [{section}]`.
    ///
    /// The `unset` prefix is present for any server other than the local one
    /// (`redis_host` absent, `localhost` or a loopback address): the host's
    /// `REDISCLI_AUTH` is only sent to a local server.
    #[must_use]
    pub fn build_info_command(
        redis_host: Option<&str>,
        redis_port: Option<u16>,
        section: Option<&str>,
        redis_password: Option<&str>,
    ) -> String {
        let mut cmd = client_prefix(redis_host, redis_port, redis_password);

        cmd.push_str(" INFO");

        if let Some(s) = section {
            let _ = write!(cmd, " {}", shell_escape(s));
        }

        cmd
    }

    /// Validate that a Redis command starts with an allowed keyword.
    ///
    /// Blocks dangerous commands like `FLUSHALL`, `FLUSHDB`, `SHUTDOWN`, `EVAL`,
    /// `SCRIPT`, and `BGSAVE`.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the command is not in the allow-list.
    pub fn validate_redis_command(command: &str) -> Result<()> {
        const ALLOWED: &[&str] = &[
            // String operations
            "GET",
            "SET",
            "DEL",
            "EXISTS",
            "EXPIRE",
            "TTL",
            "PTTL",
            "TYPE",
            "RENAME",
            "PERSIST",
            "KEYS",
            "SCAN",
            "MGET",
            "MSET",
            "INCR",
            "DECR",
            "INCRBY",
            "DECRBY",
            "APPEND",
            "STRLEN",
            "GETRANGE",
            "SETRANGE",
            "SETNX",
            "SETEX",
            "PSETEX",
            "GETSET",
            "GETDEL",
            // Hash operations
            "HGET",
            "HSET",
            "HDEL",
            "HEXISTS",
            "HGETALL",
            "HKEYS",
            "HVALS",
            "HLEN",
            "HMGET",
            "HMSET",
            "HINCRBY",
            "HSCAN",
            // List operations
            "LPUSH",
            "RPUSH",
            "LPOP",
            "RPOP",
            "LRANGE",
            "LLEN",
            "LINDEX",
            "LSET",
            "LREM",
            "LTRIM",
            // Set operations
            "SADD",
            "SREM",
            "SMEMBERS",
            "SISMEMBER",
            "SCARD",
            "SUNION",
            "SINTER",
            "SDIFF",
            "SSCAN",
            // Sorted set operations
            "ZADD",
            "ZREM",
            "ZRANGE",
            "ZRANGEBYSCORE",
            "ZREVRANGE",
            "ZRANK",
            "ZSCORE",
            "ZCARD",
            "ZCOUNT",
            "ZSCAN",
            // General/info
            "PING",
            "ECHO",
            "INFO",
            "DBSIZE",
            "TIME",
            "LASTSAVE",
            "SLOWLOG",
            "OBJECT",
            "MEMORY",
            "CLIENT",
            "PUBSUB",
            "SELECT",
            "DUMP",
            "RESTORE",
        ];
        let first_word = command.split_whitespace().next().unwrap_or("");
        let upper = first_word.to_uppercase();
        if ALLOWED.contains(&upper.as_str()) {
            Ok(())
        } else {
            Err(BridgeError::CommandDenied {
                reason: format!(
                    "Redis command '{first_word}' is not allowed. Dangerous commands \
                     (FLUSHALL, FLUSHDB, SHUTDOWN, EVAL, SCRIPT, etc.) are blocked."
                ),
            })
        }
    }

    /// Build a `redis-cli` command for arbitrary operations.
    ///
    /// Constructs: `[unset REDISCLI_AUTH VALKEYCLI_AUTH && ] [printf '%s\n' {password} | ]
    /// redis-cli [--askpass] [-h {host}] [-p {port}] {command}`.
    #[must_use]
    pub fn build_cli_command(
        redis_host: Option<&str>,
        redis_port: Option<u16>,
        command: &str,
        redis_password: Option<&str>,
    ) -> String {
        let mut cmd = client_prefix(redis_host, redis_port, redis_password);
        let _ = write!(cmd, " {}", shell_escape(command));
        cmd
    }

    /// Build a `redis-cli SCAN` command to find keys.
    ///
    /// Uses SCAN instead of KEYS to avoid blocking.
    /// Constructs: `[unset REDISCLI_AUTH VALKEYCLI_AUTH && ] [printf '%s\n' {password} | ]
    /// redis-cli [--askpass] [-h {host}] [-p {port}] --scan --pattern {pattern}
    /// [--count {n}]`.
    #[must_use]
    pub fn build_keys_command(
        redis_host: Option<&str>,
        redis_port: Option<u16>,
        pattern: Option<&str>,
        count: Option<u32>,
        redis_password: Option<&str>,
    ) -> String {
        let mut cmd = client_prefix(redis_host, redis_port, redis_password);

        let pat = pattern.unwrap_or("*");
        let _ = write!(cmd, " --scan --pattern {}", shell_escape(pat));

        if let Some(c) = count {
            let _ = write!(cmd, " --count {c}");
        }

        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_info_default() {
        let cmd = RedisCommandBuilder::build_info_command(None, None, None, None);
        assert_eq!(cmd, "redis-cli INFO");
    }

    #[test]
    fn test_info_with_host_port() {
        let cmd = RedisCommandBuilder::build_info_command(Some("10.0.0.1"), Some(6380), None, None);
        assert!(cmd.contains("-h '10.0.0.1'"));
        assert!(cmd.contains("-p 6380"));
    }

    #[test]
    fn test_info_with_section() {
        let cmd = RedisCommandBuilder::build_info_command(None, None, Some("memory"), None);
        assert!(cmd.contains("INFO 'memory'"));
    }

    #[test]
    fn test_cli_command() {
        let cmd = RedisCommandBuilder::build_cli_command(None, None, "GET mykey", None);
        assert_eq!(cmd, "redis-cli 'GET mykey'");
    }

    #[test]
    fn test_cli_with_host() {
        let cmd =
            RedisCommandBuilder::build_cli_command(Some("redis.local"), Some(6379), "PING", None);
        assert!(cmd.contains("-h 'redis.local'"));
        assert!(cmd.contains("-p 6379"));
        assert!(cmd.contains("PING"));
    }

    #[test]
    fn test_keys_default() {
        let cmd = RedisCommandBuilder::build_keys_command(None, None, None, None, None);
        assert!(cmd.contains("--scan --pattern '*'"));
    }

    #[test]
    fn test_keys_with_pattern() {
        let cmd = RedisCommandBuilder::build_keys_command(None, None, Some("user:*"), None, None);
        assert!(cmd.contains("--pattern 'user:*'"));
    }

    #[test]
    fn test_keys_with_count() {
        let cmd = RedisCommandBuilder::build_keys_command(None, None, None, Some(100), None);
        assert!(cmd.contains("--count 100"));
    }

    // ============== Shell Injection Prevention ==============

    #[test]
    fn test_info_injection_in_host() {
        let cmd = RedisCommandBuilder::build_info_command(
            Some("redis.local; rm -rf /"),
            None,
            None,
            None,
        );
        assert!(cmd.contains("-h 'redis.local; rm -rf /'"));
    }

    #[test]
    fn test_info_injection_in_section() {
        let cmd = RedisCommandBuilder::build_info_command(None, None, Some("memory; whoami"), None);
        assert!(cmd.contains("INFO 'memory; whoami'"));
    }

    #[test]
    fn test_keys_injection_in_pattern() {
        let cmd =
            RedisCommandBuilder::build_keys_command(None, None, Some("*; rm -rf /"), None, None);
        assert!(cmd.contains("--pattern '*; rm -rf /'"));
    }

    #[test]
    fn test_cli_command_escaped() {
        let cmd = RedisCommandBuilder::build_cli_command(None, None, "GET key; rm -rf /", None);
        assert!(cmd.contains("'GET key; rm -rf /'"));
    }

    #[test]
    fn test_validate_redis_command_allowed() {
        assert!(RedisCommandBuilder::validate_redis_command("GET mykey").is_ok());
        assert!(RedisCommandBuilder::validate_redis_command("SET key value").is_ok());
        assert!(RedisCommandBuilder::validate_redis_command("HGETALL myhash").is_ok());
        assert!(RedisCommandBuilder::validate_redis_command("PING").is_ok());
        assert!(RedisCommandBuilder::validate_redis_command("INFO").is_ok());
        assert!(RedisCommandBuilder::validate_redis_command("KEYS *").is_ok());
    }

    #[test]
    fn test_validate_redis_command_denied() {
        assert!(RedisCommandBuilder::validate_redis_command("FLUSHALL").is_err());
        assert!(RedisCommandBuilder::validate_redis_command("FLUSHDB").is_err());
        assert!(RedisCommandBuilder::validate_redis_command("SHUTDOWN").is_err());
        assert!(RedisCommandBuilder::validate_redis_command("SHUTDOWN NOSAVE").is_err());
        assert!(RedisCommandBuilder::validate_redis_command("EVAL script").is_err());
        assert!(RedisCommandBuilder::validate_redis_command("SCRIPT LOAD").is_err());
        assert!(RedisCommandBuilder::validate_redis_command("BGSAVE").is_err());
        assert!(RedisCommandBuilder::validate_redis_command("CONFIG SET").is_err());
    }

    #[test]
    fn test_validate_redis_command_case_insensitive() {
        assert!(RedisCommandBuilder::validate_redis_command("get mykey").is_ok());
        assert!(RedisCommandBuilder::validate_redis_command("flushall").is_err());
    }

    // ============== All-Options Combination ==============

    #[test]
    fn test_info_all_options() {
        let cmd = RedisCommandBuilder::build_info_command(
            Some("redis.prod"),
            Some(6380),
            Some("replication"),
            None,
        );
        assert!(cmd.contains("-h 'redis.prod'"));
        assert!(cmd.contains("-p 6380"));
        assert!(cmd.contains("INFO 'replication'"));
    }

    #[test]
    fn test_cli_all_options() {
        let cmd = RedisCommandBuilder::build_cli_command(
            Some("redis.prod"),
            Some(6380),
            "SET mykey myvalue",
            None,
        );
        assert!(cmd.contains("-h 'redis.prod'"));
        assert!(cmd.contains("-p 6380"));
        assert!(cmd.contains("'SET mykey myvalue'"));
    }

    #[test]
    fn test_keys_all_options() {
        let cmd = RedisCommandBuilder::build_keys_command(
            Some("redis.prod"),
            Some(6380),
            Some("session:*"),
            Some(200),
            None,
        );
        assert!(cmd.contains("-h 'redis.prod'"));
        assert!(cmd.contains("-p 6380"));
        assert!(cmd.contains("--pattern 'session:*'"));
        assert!(cmd.contains("--count 200"));
    }

    // ============== Minimal Command Tests ==============

    #[test]
    fn test_cli_minimal() {
        let cmd = RedisCommandBuilder::build_cli_command(None, None, "PING", None);
        assert_eq!(cmd, "redis-cli 'PING'");
    }

    // ============== Edge Cases ==============

    #[test]
    fn test_info_host_with_single_quotes() {
        let cmd = RedisCommandBuilder::build_info_command(Some("it's-redis"), None, None, None);
        assert!(cmd.contains("-h 'it'\\''s-redis'"));
    }

    #[test]
    fn test_info_port_boundary_low() {
        let cmd = RedisCommandBuilder::build_info_command(None, Some(1), None, None);
        assert!(cmd.contains("-p 1"));
    }

    #[test]
    fn test_info_port_boundary_high() {
        let cmd = RedisCommandBuilder::build_info_command(None, Some(65535), None, None);
        assert!(cmd.contains("-p 65535"));
    }

    #[test]
    fn test_keys_pattern_complex_glob() {
        let cmd = RedisCommandBuilder::build_keys_command(
            None,
            None,
            Some("user:*:session:*"),
            None,
            None,
        );
        assert!(cmd.contains("--pattern 'user:*:session:*'"));
    }

    #[test]
    fn test_keys_count_zero() {
        let cmd = RedisCommandBuilder::build_keys_command(None, None, None, Some(0), None);
        assert!(cmd.contains("--count 0"));
    }

    #[test]
    fn test_keys_count_large() {
        let cmd = RedisCommandBuilder::build_keys_command(None, None, None, Some(100_000), None);
        assert!(cmd.contains("--count 100000"));
    }

    #[test]
    fn test_info_host_only() {
        let cmd = RedisCommandBuilder::build_info_command(Some("10.0.0.1"), None, None, None);
        assert!(cmd.contains("-h '10.0.0.1'"));
        assert!(!cmd.contains("-p"));
    }

    #[test]
    fn test_info_port_only() {
        let cmd = RedisCommandBuilder::build_info_command(None, Some(6380), None, None);
        assert!(cmd.contains("-p 6380"));
        assert!(!cmd.contains("-h"));
    }

    #[test]
    fn test_keys_no_count() {
        let cmd = RedisCommandBuilder::build_keys_command(None, None, Some("*"), None, None);
        assert!(!cmd.contains("--count"));
    }

    #[test]
    fn test_cli_empty_command() {
        let cmd = RedisCommandBuilder::build_cli_command(None, None, "", None);
        assert_eq!(cmd, "redis-cli ''");
    }

    // ============== Stored credential stays on the local server ==============

    const UNSET: &str = "unset REDISCLI_AUTH VALKEYCLI_AUTH && ";

    #[test]
    fn test_local_golden_strings_are_unchanged() {
        for host in [
            None,
            Some("localhost"),
            Some("LOCALHOST"),
            Some("127.0.0.1"),
            Some("::1"),
        ] {
            let h = host.map_or_else(String::new, |h| format!(" -h '{h}'"));
            assert_eq!(
                RedisCommandBuilder::build_info_command(host, Some(6380), Some("memory"), None),
                format!("redis-cli{h} -p 6380 INFO 'memory'")
            );
            assert_eq!(
                RedisCommandBuilder::build_cli_command(host, Some(6380), "GET k", None),
                format!("redis-cli{h} -p 6380 'GET k'")
            );
            assert_eq!(
                RedisCommandBuilder::build_keys_command(
                    host,
                    Some(6380),
                    Some("u:*"),
                    Some(50),
                    None
                ),
                format!("redis-cli{h} -p 6380 --scan --pattern 'u:*' --count 50")
            );
        }
        assert_eq!(
            RedisCommandBuilder::build_info_command(None, None, None, None),
            "redis-cli INFO"
        );
    }

    #[test]
    fn test_remote_golden_strings_without_password() {
        assert_eq!(
            RedisCommandBuilder::build_info_command(
                Some("redis.example.com"),
                Some(6380),
                Some("memory"),
                None
            ),
            "unset REDISCLI_AUTH VALKEYCLI_AUTH && redis-cli -h 'redis.example.com' -p 6380 INFO 'memory'"
        );
        assert_eq!(
            RedisCommandBuilder::build_cli_command(Some("10.0.0.5"), None, "GET k", None),
            "unset REDISCLI_AUTH VALKEYCLI_AUTH && redis-cli -h '10.0.0.5' 'GET k'"
        );
        assert_eq!(
            RedisCommandBuilder::build_keys_command(
                Some("redis.example.com"),
                Some(6379),
                Some("u:*"),
                Some(50),
                None
            ),
            "unset REDISCLI_AUTH VALKEYCLI_AUTH && redis-cli -h 'redis.example.com' -p 6379 \
             --scan --pattern 'u:*' --count 50"
        );
    }

    #[test]
    fn test_remote_golden_strings_with_password() {
        assert_eq!(
            RedisCommandBuilder::build_info_command(
                Some("redis.example.com"),
                Some(6380),
                Some("memory"),
                Some("s3cret")
            ),
            "unset REDISCLI_AUTH VALKEYCLI_AUTH && printf '%s\\n' 's3cret' | redis-cli --askpass \
             -h 'redis.example.com' -p 6380 INFO 'memory'"
        );
        assert_eq!(
            RedisCommandBuilder::build_cli_command(Some("10.0.0.5"), None, "GET k", Some("s3cret")),
            "unset REDISCLI_AUTH VALKEYCLI_AUTH && printf '%s\\n' 's3cret' | redis-cli --askpass \
             -h '10.0.0.5' 'GET k'"
        );
        assert_eq!(
            RedisCommandBuilder::build_keys_command(
                Some("redis.example.com"),
                None,
                None,
                None,
                Some("s3cret")
            ),
            "unset REDISCLI_AUTH VALKEYCLI_AUTH && printf '%s\\n' 's3cret' | redis-cli --askpass \
             -h 'redis.example.com' --scan --pattern '*'"
        );
    }

    #[test]
    fn test_local_golden_strings_with_password() {
        assert_eq!(
            RedisCommandBuilder::build_info_command(None, Some(6380), None, Some("s3cret")),
            "printf '%s\\n' 's3cret' | redis-cli --askpass -p 6380 INFO"
        );
        assert_eq!(
            RedisCommandBuilder::build_cli_command(Some("localhost"), None, "PING", Some("s3cret")),
            "printf '%s\\n' 's3cret' | redis-cli --askpass -h 'localhost' 'PING'"
        );
        assert_eq!(
            RedisCommandBuilder::build_keys_command(
                Some("127.0.0.1"),
                None,
                Some("k"),
                None,
                Some("s3cret")
            ),
            "printf '%s\\n' 's3cret' | redis-cli --askpass -h '127.0.0.1' --scan --pattern 'k'"
        );
    }

    #[test]
    fn test_unset_prefix_only_for_other_servers() {
        for host in [
            "redis.example.com",
            "10.0.0.5",
            "127.1",
            "0.0.0.0",
            "localhost.example.com",
            "::2",
            "",
        ] {
            let cmd = RedisCommandBuilder::build_cli_command(Some(host), None, "PING", None);
            assert!(cmd.starts_with(UNSET), "{host}: {cmd}");
        }
        for host in [
            "localhost",
            "LocalHost",
            "127.0.0.1",
            "127.0.0.2",
            "::1",
            "::ffff:127.0.0.1",
        ] {
            let cmd = RedisCommandBuilder::build_cli_command(Some(host), None, "PING", None);
            assert!(!cmd.contains("unset"), "{host}: {cmd}");
        }
    }

    #[test]
    fn test_password_never_in_redis_cli_argv() {
        for host in [None, Some("redis.example.com")] {
            let cmds = [
                RedisCommandBuilder::build_info_command(host, None, None, Some("pw")),
                RedisCommandBuilder::build_cli_command(host, None, "PING", Some("pw")),
                RedisCommandBuilder::build_keys_command(host, None, None, None, Some("pw")),
            ];
            for cmd in cmds {
                assert!(!cmd.contains(" -a "), "{cmd}");
                assert!(cmd.contains("redis-cli --askpass"), "{cmd}");
                let (feed, client) = cmd.split_once(" | ").expect("pipeline");
                assert!(feed.ends_with("printf '%s\\n' 'pw'"), "{cmd}");
                assert!(!client.contains("pw"), "{cmd}");
            }
        }
    }

    #[test]
    fn test_password_is_single_quote_escaped() {
        let cmd = RedisCommandBuilder::build_cli_command(None, None, "PING", Some("a'b;$(x)%s"));
        assert_eq!(
            cmd,
            "printf '%s\\n' 'a'\\''b;$(x)%s' | redis-cli --askpass 'PING'"
        );
    }

    // ============== Argument validation ==============

    fn denied(result: Result<()>, arg: &str) {
        match result {
            Err(BridgeError::CommandDenied { reason }) => {
                assert!(reason.contains(&format!("'{arg}'")), "{reason}");
            }
            other => panic!("expected CommandDenied naming {arg}, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_connection_accepts_hosts() {
        let longest = "a".repeat(253);
        for host in [
            "localhost",
            "LOCALHOST",
            "127.0.0.2",
            "::1",
            "::ffff:127.0.0.1",
            "redis.example.com",
            "10.0.0.5",
            "fe80::1%eth0",
            "my_redis-1",
            longest.as_str(),
        ] {
            RedisCommandBuilder::validate_connection(Some(host), None)
                .unwrap_or_else(|e| panic!("{host}: {e:?}"));
        }
        RedisCommandBuilder::validate_connection(None, None).unwrap();
    }

    #[test]
    fn test_validate_connection_refuses_hosts() {
        let too_long = "a".repeat(254);
        for host in [
            "",
            "-x",
            "--help",
            "a b",
            "a,b",
            "é",
            "a;b",
            "a'b",
            "[::1]",
            "a\nb",
            too_long.as_str(),
        ] {
            denied(
                RedisCommandBuilder::validate_connection(Some(host), None),
                "redis_host",
            );
        }
    }

    #[test]
    fn test_validate_connection_empty_host_says_omit() {
        match RedisCommandBuilder::validate_connection(Some(""), None) {
            Err(BridgeError::CommandDenied { reason }) => {
                assert!(reason.contains("omit it for the local server"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_validate_connection_passwords() {
        let longest = "p".repeat(1024);
        let too_long = "p".repeat(1025);
        for pw in ["s3cret", "a b", "é'\"$`;|&", "%s\\n", longest.as_str()] {
            RedisCommandBuilder::validate_connection(Some("redis.example.com"), Some(pw))
                .unwrap_or_else(|e| panic!("{pw}: {e:?}"));
        }
        for pw in [
            "",
            "a\nb",
            "a\rb",
            "a\0b",
            "a\tb",
            "a\x1bb",
            "a\x7fb",
            "\n",
            too_long.as_str(),
        ] {
            denied(
                RedisCommandBuilder::validate_connection(Some("redis.example.com"), Some(pw)),
                "redis_password",
            );
            denied(
                RedisCommandBuilder::validate_connection(None, Some(pw)),
                "redis_password",
            );
        }
    }

    #[test]
    fn test_validate_connection_no_refusal_without_password() {
        // An unauthenticated remote Redis is legitimate.
        RedisCommandBuilder::validate_connection(Some("redis.example.com"), None).unwrap();
    }
}
