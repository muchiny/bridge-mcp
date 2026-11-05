//! Vault Command Builder
//!
//! Builds `HashiCorp` Vault CLI commands for remote execution via SSH.
//! Supports status, read, list, and write operations.

use std::fmt::Write;

use crate::config::{RedactedSecret, ShellType};
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Validate that a Vault path contains only safe characters.
/// Allows: alphanumeric, slashes, hyphens, underscores, dots.
/// Rejects path traversal (`..`).
pub fn validate_vault_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Vault path cannot be empty".to_string(),
        });
    }
    if path.split('/').any(|component| component == "..") {
        return Err(BridgeError::CommandDenied {
            reason: "Path traversal ('..') is not allowed in Vault paths".to_string(),
        });
    }
    if !path
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'))
    {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid Vault path '{path}': must contain only alphanumeric characters, \
                 slashes, hyphens, underscores, or dots"
            ),
        });
    }
    Ok(())
}

/// Builds Vault CLI commands for remote execution.
pub struct VaultCommandBuilder;

impl VaultCommandBuilder {
    /// Build a `vault status` command.
    ///
    /// Constructs: `vault status [-format={fmt}]`
    ///
    /// The Vault server address is deliberately not a parameter: the CLI sends
    /// the host's Vault token to whatever `VAULT_ADDR` names, so the remote
    /// environment's own `VAULT_ADDR` is the only one that may apply.
    #[must_use]
    pub fn build_status_command(output_format: Option<&str>) -> String {
        let mut cmd = String::from("vault status");

        if let Some(fmt) = output_format {
            let _ = write!(cmd, " -format={}", shell_escape(fmt));
        }

        cmd
    }

    /// Build a `vault kv get` command.
    ///
    /// Constructs: `vault kv get [-mount={mount}] [-format={fmt}] [-field={f}] -- {path}`
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `path` contains unsafe characters.
    pub fn build_read_command(
        path: &str,
        mount: Option<&str>,
        field: Option<&str>,
        output_format: Option<&str>,
    ) -> Result<String> {
        validate_vault_path(path)?;
        let mut cmd = String::from("vault kv get");

        if let Some(m) = mount {
            let _ = write!(cmd, " -mount={}", shell_escape(m));
        }

        if let Some(fmt) = output_format {
            let _ = write!(cmd, " -format={}", shell_escape(fmt));
        }

        if let Some(f) = field {
            let _ = write!(cmd, " -field={}", shell_escape(f));
        }

        // `--`: the path (allowed to start with `-`) must not be read as a flag.
        let _ = write!(cmd, " -- {}", shell_escape(path));
        Ok(cmd)
    }

    /// Build a `vault kv list` command.
    ///
    /// Constructs: `vault kv list [-mount={mount}] [-format={fmt}] -- {path}`
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `path` contains unsafe characters.
    pub fn build_list_command(
        path: &str,
        mount: Option<&str>,
        output_format: Option<&str>,
    ) -> Result<String> {
        validate_vault_path(path)?;
        let mut cmd = String::from("vault kv list");

        if let Some(m) = mount {
            let _ = write!(cmd, " -mount={}", shell_escape(m));
        }

        if let Some(fmt) = output_format {
            let _ = write!(cmd, " -format={}", shell_escape(fmt));
        }

        // `--`: the path (allowed to start with `-`) must not be read as a flag.
        let _ = write!(cmd, " -- {}", shell_escape(path));
        Ok(cmd)
    }

    /// Check the arguments of `vault kv put` that are refused rather than
    /// escaped: the path and the `data` entries. Run by the tool's `validate`
    /// (so the refusal is audited) and again by [`Self::build_write_command`].
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `path` is refused, `data` is
    /// empty, an entry has no `=` or an empty key, or a key is repeated. The
    /// message names the entry's position (or the repeated key), never a value.
    pub fn validate_write_args(path: &str, data: &[RedactedSecret]) -> Result<()> {
        validate_vault_path(path)?;
        data_to_json(data).map(drop)
    }

    /// Build a `vault kv put` command.
    ///
    /// Constructs:
    /// ```text
    /// vault kv put [-mount={mount}] -- {path} - <<'VAULT_DATA_EOF_<uuid>'
    /// {"k1":"v1","k2":"v2"}
    /// VAULT_DATA_EOF_<uuid>
    /// ```
    ///
    /// **FIND-031 (Sprint 2 Task 21):** the data is sent on the stdin of
    /// `vault` (`-` argument + heredoc) instead of being appended to argv.
    /// The previous shape `vault kv put path key=secret_value` exposed every
    /// secret value to anyone running `ps eww` on the remote host for the
    /// lifetime of the vault process. Note that the heredoc body is part of the
    /// command string, so the login shell's own `-c` argument (and `sudo`'s,
    /// when elevated) still carries it: the guarantee covers the `vault`
    /// process only, which is why the tool refuses `sudo`.
    ///
    /// `vault kv put PATH -` reads **one JSON object** from stdin (a `key=value`
    /// body is rejected by vault), so the entries are folded into a JSON object
    /// with `serde_json`: keys and values are string-escaped, and the body is a
    /// single line that starts with `{`. The heredoc body is shell-literal
    /// (single-quoted terminator, no expansion) and the terminator is
    /// randomized per call; the body being one line starting with `{`, it can
    /// never equal the terminator, so no value can close the heredoc early.
    /// Same heredoc pattern as `template_apply` (commit 2da5d55).
    ///
    /// `data` carries `key=value` entries (split at the first `=`); values are
    /// typically secrets, so the caller is expected to pass [`RedactedSecret`]
    /// (FIND-030) to avoid gratuitous heap residency and to make the pairs
    /// leak-proof under `Debug`/`Display`/`Serialize`. The slice is borrowed
    /// immutably here; the owner controls when the secret bytes are wiped.
    /// Each element is read here through the audited plaintext boundary
    /// (`as_str`) only to assemble the JSON body.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] under the conditions of
    /// [`Self::validate_write_args`].
    pub fn build_write_command(
        path: &str,
        data: &[RedactedSecret],
        mount: Option<&str>,
    ) -> Result<String> {
        Self::validate_write_args(path, data)?;
        let body = data_to_json(data)?;
        let mut cmd = String::from("vault kv put");

        if let Some(m) = mount {
            let _ = write!(cmd, " -mount={}", shell_escape(m));
        }

        // `--`: the path (allowed to start with `-`) must not be read as a flag.
        let _ = write!(cmd, " -- {}", shell_escape(path));

        let terminator = format!("VAULT_DATA_EOF_{}", uuid::Uuid::new_v4().simple());
        let _ = writeln!(cmd, " - <<'{terminator}'");
        let _ = writeln!(cmd, "{body}");
        cmd.push_str(&terminator);

        Ok(cmd)
    }
}

/// Fold `key=value` entries into the single-line JSON object that
/// `vault kv put PATH -` reads from stdin.
///
/// Each entry is split at its first `=`; the value may itself contain `=`.
fn data_to_json(data: &[RedactedSecret]) -> Result<String> {
    let denied = |reason: String| BridgeError::CommandDenied { reason };
    if data.is_empty() {
        return Err(denied(
            "'data' needs at least one key=value entry".to_string(),
        ));
    }
    let mut object = serde_json::Map::new();
    for (index, entry) in data.iter().enumerate() {
        let position = index.saturating_add(1);
        let Some((key, value)) = entry.as_str().split_once('=') else {
            return Err(denied(format!(
                "'data' entry {position} is not a key=value pair (no '=')"
            )));
        };
        if key.is_empty() {
            return Err(denied(format!("'data' entry {position} has an empty key")));
        }
        let previous = object.insert(
            key.to_string(),
            serde_json::Value::String(value.to_string()),
        );
        if previous.is_some() {
            return Err(denied(format!(
                "'data' repeats the key '{key}' (entry {position})"
            )));
        }
    }
    serde_json::to_string(&object)
        .map_err(|_| denied("'data' cannot be serialized as a JSON object".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The JSON object that `vault` would read from the heredoc of `cmd`
    /// (line 0 is the command, then the body, then the terminator).
    fn heredoc_json(cmd: &str) -> serde_json::Value {
        let lines: Vec<&str> = cmd.lines().collect();
        assert_eq!(lines.len(), 3, "command, one body line, terminator: {cmd}");
        let terminator = lines[0].rsplit("<<").next().unwrap().trim_matches('\'');
        assert_eq!(lines[2], terminator, "{cmd}");
        serde_json::from_str(lines[1]).expect("body must be one JSON object")
    }

    #[test]
    fn test_validate_vault_path_valid() {
        assert!(validate_vault_path("secret/myapp").is_ok());
        assert!(validate_vault_path("secret/my-app/config").is_ok());
        assert!(validate_vault_path("kv/data/app_config").is_ok());
    }

    #[test]
    fn test_validate_vault_path_invalid() {
        assert!(validate_vault_path("").is_err());
        assert!(validate_vault_path("secret/$(whoami)").is_err());
        assert!(validate_vault_path("secret; rm -rf /").is_err());
    }

    #[test]
    fn test_status_default() {
        let cmd = VaultCommandBuilder::build_status_command(None);
        assert_eq!(cmd, "vault status");
    }

    #[test]
    fn test_no_builder_sets_vault_addr() {
        // The remote environment's own VAULT_ADDR applies: a caller-chosen
        // address would receive the host's Vault token.
        let data = vec![RedactedSecret::from("k=v")];
        let cmds = [
            VaultCommandBuilder::build_status_command(Some("json")),
            VaultCommandBuilder::build_read_command(
                "secret/a",
                Some("kv"),
                Some("f"),
                Some("json"),
            )
            .unwrap(),
            VaultCommandBuilder::build_list_command("secret/", Some("kv"), Some("json")).unwrap(),
            VaultCommandBuilder::build_write_command("secret/a", &data, Some("kv")).unwrap(),
        ];
        for cmd in cmds {
            assert!(cmd.starts_with("vault "), "{cmd}");
            assert!(!cmd.contains("VAULT_ADDR"), "{cmd}");
        }
    }

    #[test]
    fn test_status_json() {
        let cmd = VaultCommandBuilder::build_status_command(Some("json"));
        assert!(cmd.contains("-format='json'"));
    }

    #[test]
    fn test_read_simple() {
        let cmd =
            VaultCommandBuilder::build_read_command("secret/myapp", None, None, None).unwrap();
        assert!(cmd.contains("vault kv get -- 'secret/myapp'"));
    }

    #[test]
    fn test_read_with_mount() {
        let cmd =
            VaultCommandBuilder::build_read_command("myapp/config", Some("secret"), None, None)
                .unwrap();
        assert!(cmd.contains("-mount='secret'"));
        assert!(cmd.contains("'myapp/config'"));
    }

    #[test]
    fn test_read_with_field() {
        let cmd =
            VaultCommandBuilder::build_read_command("secret/myapp", None, Some("password"), None)
                .unwrap();
        assert!(cmd.contains("-field='password'"));
    }

    #[test]
    fn test_list_simple() {
        let cmd = VaultCommandBuilder::build_list_command("secret/", None, None).unwrap();
        assert!(cmd.contains("vault kv list -- 'secret/'"));
    }

    #[test]
    fn test_list_json() {
        let cmd = VaultCommandBuilder::build_list_command("secret/", None, Some("json")).unwrap();
        assert!(cmd.contains("-format='json'"));
    }

    #[test]
    fn test_write_simple() {
        let data = vec![
            RedactedSecret::from("username=admin"),
            RedactedSecret::from("password=secret"),
        ];
        let cmd = VaultCommandBuilder::build_write_command("secret/myapp", &data, None).unwrap();
        // FIND-031: argv is `vault kv put -- 'path' - <<'TERMINATOR'`; values
        // live in the heredoc body, not as argv-visible `key=value` pairs.
        assert!(cmd.contains("vault kv put -- 'secret/myapp' - <<"));
        // `vault kv put PATH -` reads one JSON object from stdin.
        assert_eq!(
            heredoc_json(&cmd),
            serde_json::json!({"username": "admin", "password": "secret"})
        );
    }

    #[test]
    fn test_write_with_mount() {
        let data = vec![RedactedSecret::from("key=value")];
        let cmd =
            VaultCommandBuilder::build_write_command("myapp/config", &data, Some("kv")).unwrap();
        assert!(cmd.contains("-mount='kv'"));
    }

    // ============== Shell Injection Prevention ==============

    #[test]
    fn test_status_injection_in_format() {
        let cmd = VaultCommandBuilder::build_status_command(Some("json; whoami"));
        assert_eq!(cmd, "vault status -format='json; whoami'");
    }

    #[test]
    fn test_write_injection_in_data_value() {
        let data = vec![RedactedSecret::from("password=s3cr3t; rm -rf /")];
        let cmd = VaultCommandBuilder::build_write_command("secret/app", &data, None).unwrap();
        // FIND-031: value is a JSON string in the heredoc body (single-quoted
        // terminator disables shell expansion), so `;` and `rm -rf /` are
        // literal data, not shell metacharacters.
        assert_eq!(
            heredoc_json(&cmd),
            serde_json::json!({"password": "s3cr3t; rm -rf /"})
        );
    }

    #[test]
    fn test_read_injection_in_field() {
        let cmd = VaultCommandBuilder::build_read_command(
            "secret/app",
            None,
            Some("$(cat /etc/passwd)"),
            None,
        )
        .unwrap();
        assert!(cmd.contains("-field='$(cat /etc/passwd)'"));
    }

    // ============== All-Options Combination ==============

    #[test]
    fn test_read_all_options() {
        let cmd = VaultCommandBuilder::build_read_command(
            "secret/myapp",
            Some("kv"),
            Some("password"),
            Some("json"),
        )
        .unwrap();
        assert!(cmd.contains("-mount='kv'"));
        assert!(cmd.contains("-format='json'"));
        assert!(cmd.contains("-field='password'"));
        assert!(cmd.contains("'secret/myapp'"));
    }

    #[test]
    fn test_list_all_options() {
        let cmd = VaultCommandBuilder::build_list_command("secret/apps/", Some("kv"), Some("json"))
            .unwrap();
        assert!(cmd.contains("-mount='kv'"));
        assert!(cmd.contains("-format='json'"));
        assert!(cmd.contains("'secret/apps/'"));
    }

    #[test]
    fn test_write_all_options() {
        let data = vec![
            RedactedSecret::from("user=admin"),
            RedactedSecret::from("pass=secret"),
        ];
        let cmd =
            VaultCommandBuilder::build_write_command("secret/myapp", &data, Some("kv")).unwrap();
        assert!(cmd.contains("-mount='kv'"));
        assert!(cmd.contains("'secret/myapp'"));
        // FIND-031: values are in the heredoc body, not argv args.
        assert_eq!(
            heredoc_json(&cmd),
            serde_json::json!({"user": "admin", "pass": "secret"})
        );
    }

    #[test]
    fn test_status_all_options() {
        let cmd = VaultCommandBuilder::build_status_command(Some("json"));
        assert_eq!(cmd, "vault status -format='json'");
    }

    // ============== Edge Cases ==============

    #[test]
    fn test_write_empty_data_is_refused() {
        let data: Vec<RedactedSecret> = vec![];
        let err =
            VaultCommandBuilder::build_write_command("secret/myapp", &data, None).unwrap_err();
        assert!(matches!(err, BridgeError::CommandDenied { .. }), "{err:?}");
    }

    #[test]
    fn test_write_single_data_item() {
        let data = vec![RedactedSecret::from("key=val")];
        let cmd = VaultCommandBuilder::build_write_command("secret/myapp", &data, None).unwrap();
        // FIND-031: shape is `... 'secret/myapp' - <<'TERMINATOR'\n{json}\nTERMINATOR`.
        assert!(cmd.contains("'secret/myapp' - <<"));
        assert_eq!(heredoc_json(&cmd), serde_json::json!({"key": "val"}));
    }

    #[test]
    fn test_write_data_with_single_quotes() {
        let data = vec![RedactedSecret::from("msg=it's secret")];
        let cmd = VaultCommandBuilder::build_write_command("secret/app", &data, None).unwrap();
        // FIND-031: heredoc body is shell-literal; the apostrophe is preserved
        // verbatim, no shell-escape needed (the single-quoted terminator
        // disables expansion).
        assert!(cmd.contains("\n{\"msg\":\"it's secret\"}\n"));
        assert_eq!(
            heredoc_json(&cmd),
            serde_json::json!({"msg": "it's secret"})
        );
    }

    #[test]
    fn test_read_minimal() {
        let cmd =
            VaultCommandBuilder::build_read_command("secret/myapp", None, None, None).unwrap();
        assert_eq!(cmd, "vault kv get -- 'secret/myapp'");
    }

    #[test]
    fn test_list_minimal() {
        let cmd = VaultCommandBuilder::build_list_command("secret/", None, None).unwrap();
        assert_eq!(cmd, "vault kv list -- 'secret/'");
    }

    // ============== validate_vault_path Additional Tests ==============

    #[test]
    fn test_validate_vault_path_with_dots() {
        assert!(validate_vault_path("secret/v1.0/config").is_ok());
    }

    #[test]
    fn test_validate_vault_path_with_underscores() {
        assert!(validate_vault_path("kv/my_app/data_config").is_ok());
    }

    #[test]
    fn test_validate_vault_path_with_spaces() {
        assert!(validate_vault_path("secret/my app").is_err());
    }

    #[test]
    fn test_validate_vault_path_with_pipe() {
        assert!(validate_vault_path("secret/app|cmd").is_err());
    }

    #[test]
    fn test_validate_vault_path_with_ampersand() {
        assert!(validate_vault_path("secret/app&data").is_err());
    }

    #[test]
    fn test_validate_vault_path_with_backtick() {
        assert!(validate_vault_path("secret/`whoami`").is_err());
    }

    #[test]
    fn test_validate_vault_path_traversal_rejected() {
        assert!(validate_vault_path("secret/../etc/shadow").is_err());
        assert!(validate_vault_path("../secret/data").is_err());
        assert!(validate_vault_path("secret/data/..").is_err());
    }

    #[test]
    fn test_validate_vault_path_single_dot_allowed() {
        assert!(validate_vault_path("secret/v1.0/config").is_ok());
        assert!(validate_vault_path("secret/my.app").is_ok());
    }

    // ============== FIND-031: argv leak prevention ==============

    /// FIND-031: secrets must not appear as `vault kv put path KEY=VALUE`
    /// because the remote process's `ps eww` would expose `VALUE`.
    /// Instead the builder pipes a stdin heredoc whose body is shell-literal
    /// (single-quoted terminator), so `VALUE` lives in the kernel pipe buffer
    /// and never in argv.
    #[test]
    fn vault_write_excludes_secret_value_from_argv() {
        let data = vec![RedactedSecret::from("k=topsecret")];
        let cmd = VaultCommandBuilder::build_write_command("secret/foo", &data, None).unwrap();

        // Split on `<<` — anything before is argv, anything after is the
        // heredoc construct (terminator + body). Secret may appear in the
        // body, never in argv.
        let argv_only = cmd.split("<<").next().unwrap();
        assert!(
            !argv_only.contains("topsecret"),
            "FIND-031: secret leaked into argv portion of command: {cmd}"
        );
    }

    /// FIND-031: the builder must use a stdin pipe (`-` argument + heredoc).
    #[test]
    fn vault_write_uses_stdin_heredoc() {
        let data = vec![RedactedSecret::from("k=v")];
        let cmd = VaultCommandBuilder::build_write_command("secret/foo", &data, None).unwrap();

        assert!(
            cmd.contains("vault kv put"),
            "command must still invoke vault kv put: {cmd}"
        );
        // The dash signals "read one JSON object from stdin" to vault.
        assert!(
            cmd.contains(" - <<"),
            "FIND-031: must pipe data via stdin heredoc, got: {cmd}"
        );
    }

    /// FIND-031: heredoc terminator is randomized so a malicious value
    /// cannot close the heredoc early and inject shell. Same pattern as
    /// `template_apply` (commit 2da5d55).
    #[test]
    fn vault_write_heredoc_terminator_is_randomized() {
        let data = vec![RedactedSecret::from("k=v")];
        let cmd1 = VaultCommandBuilder::build_write_command("secret/foo", &data, None).unwrap();
        let cmd2 = VaultCommandBuilder::build_write_command("secret/foo", &data, None).unwrap();
        assert_ne!(
            cmd1, cmd2,
            "heredoc terminator must be re-rolled per call to defeat injection"
        );
    }

    #[test]
    fn test_dash_path_goes_after_double_dash() {
        let get = VaultCommandBuilder::build_read_command("-x", None, None, None).unwrap();
        assert_eq!(get, "vault kv get -- '-x'");
        let list = VaultCommandBuilder::build_list_command("-x", None, None).unwrap();
        assert_eq!(list, "vault kv list -- '-x'");
        let data = vec![RedactedSecret::from("k=v")];
        let put = VaultCommandBuilder::build_write_command("-x", &data, None).unwrap();
        assert!(put.starts_with("vault kv put -- '-x' - <<"), "{put}");
    }

    // ============== stdin is one JSON object ==============

    #[test]
    fn test_write_body_is_one_json_object_with_escaping() {
        let data = vec![
            RedactedSecret::from("user=admin"),
            RedactedSecret::from("pw=a=b\"c\\d\ne"),
            RedactedSecret::from("empty="),
        ];
        let cmd = VaultCommandBuilder::build_write_command("secret/app", &data, None).unwrap();
        // The value keeps everything after the first '=', quotes, backslash
        // and newline included, and the body stays on one line.
        assert_eq!(
            heredoc_json(&cmd),
            serde_json::json!({"user": "admin", "pw": "a=b\"c\\d\ne", "empty": ""})
        );
    }

    #[test]
    fn test_write_value_equal_to_terminator_cannot_close_heredoc() {
        let data = vec![RedactedSecret::from("k=VAULT_DATA_EOF_x")];
        let cmd = VaultCommandBuilder::build_write_command("secret/app", &data, None).unwrap();
        // Three lines only: a value cannot add a line of its own.
        assert_eq!(
            heredoc_json(&cmd),
            serde_json::json!({"k": "VAULT_DATA_EOF_x"})
        );
    }

    #[test]
    fn test_write_refuses_entry_without_equals() {
        let data = vec![
            RedactedSecret::from("k=v"),
            RedactedSecret::from("s3cr3tonly"),
        ];
        let err = VaultCommandBuilder::build_write_command("secret/app", &data, None).unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, BridgeError::CommandDenied { .. }), "{msg}");
        assert!(msg.contains("entry 2"), "{msg}");
        assert!(!msg.contains("s3cr3tonly"), "value leaked: {msg}");
    }

    #[test]
    fn test_write_refuses_empty_key() {
        let data = vec![RedactedSecret::from("=v")];
        assert!(matches!(
            VaultCommandBuilder::build_write_command("secret/app", &data, None),
            Err(BridgeError::CommandDenied { .. })
        ));
    }

    #[test]
    fn test_write_refuses_duplicate_key() {
        let data = vec![RedactedSecret::from("k=1"), RedactedSecret::from("k=2")];
        let err = VaultCommandBuilder::build_write_command("secret/app", &data, None).unwrap_err();
        assert!(matches!(err, BridgeError::CommandDenied { .. }), "{err:?}");
        assert!(err.to_string().contains("'k'"), "{err}");
    }

    #[test]
    fn test_validate_write_args() {
        let ok = vec![RedactedSecret::from("k=v")];
        assert!(VaultCommandBuilder::validate_write_args("secret/app", &ok).is_ok());
        assert!(VaultCommandBuilder::validate_write_args("secret/../x", &ok).is_err());
        assert!(VaultCommandBuilder::validate_write_args("secret/$(id)", &ok).is_err());
        let bad = vec![RedactedSecret::from("novalue")];
        assert!(VaultCommandBuilder::validate_write_args("secret/app", &bad).is_err());
    }
}
