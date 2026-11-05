//! Windows Registry Command Builder
//!
//! Builds `PowerShell` and registry commands for querying, setting, listing,
//! exporting, and deleting Windows registry keys and values via SSH.

use std::fmt::Write;

use crate::config::ShellType;
use crate::domain::use_cases::shell;
use crate::error::{BridgeError, Result};

/// Escape a string for safe interpolation into a `PowerShell` command.
fn ps_escape(s: &str) -> String {
    shell::escape(s, ShellType::PowerShell)
}

/// The registry hives `reg.exe` and the `PowerShell` registry provider name.
const REGISTRY_ROOTS: [&str; 10] = [
    "HKLM",
    "HKCU",
    "HKCR",
    "HKU",
    "HKCC",
    "HKEY_LOCAL_MACHINE",
    "HKEY_CURRENT_USER",
    "HKEY_CLASSES_ROOT",
    "HKEY_USERS",
    "HKEY_CURRENT_CONFIG",
];

/// Whether `path` starts with `prefix`, ignoring ASCII case.
fn starts_with_ignore_case(path: &str, prefix: &str) -> bool {
    path.get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

/// Whether `path` is addressed to the registry provider: a drive form
/// (`HKLM:`, `HKCU:`, `HKCR:`, `HKU:`, `HKCC:`) or `Registry::HK…`. Any other
/// path (a UNC path, a drive letter, a relative name) would reach the file
/// system provider.
fn has_registry_provider_prefix(path: &str) -> bool {
    ["HKLM:", "HKCU:", "HKCR:", "HKU:", "HKCC:", "Registry::HK"]
        .iter()
        .any(|prefix| starts_with_ignore_case(path, prefix))
}

/// Validates a Windows Registry path to prevent command injection.
///
/// Registry paths must contain only alphanumeric characters, backslashes,
/// colons, hyphens, underscores, spaces, and dots, and must start with a
/// registry drive (`HKLM:`, `HKCU:`, `HKCR:`, `HKU:`, `HKCC:`) or
/// `Registry::HK…`: any other path reaches the file system provider, and a
/// UNC path (`\\host\share`) makes the Windows host authenticate to `host`.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the path is invalid.
pub fn validate_registry_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Registry path cannot be empty".to_string(),
        });
    }
    if !has_registry_provider_prefix(path) {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid registry path '{path}'. It must start with a registry drive \
                 (HKLM:, HKCU:, HKCR:, HKU:, HKCC:) or Registry::HK."
            ),
        });
    }
    if path.chars().all(|c| {
        c.is_alphanumeric() || c == '\\' || c == ':' || c == '-' || c == '_' || c == ' ' || c == '.'
    }) {
        Ok(())
    } else {
        Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid registry path '{path}'. \
                 Only alphanumeric, backslash, colon, hyphen, underscore, space, and dot allowed.",
            ),
        })
    }
}

/// Validates a Windows Registry value name to prevent command injection.
///
/// Names must contain only alphanumeric characters, hyphens, underscores,
/// spaces, and dots.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the name is invalid.
pub fn validate_registry_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Registry name cannot be empty".to_string(),
        });
    }
    if name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ' ' || c == '.')
    {
        Ok(())
    } else {
        Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid registry name '{name}'. \
                 Only alphanumeric, hyphen, underscore, space, and dot allowed.",
            ),
        })
    }
}

/// Validates the key a `reg export` is given.
///
/// The key must start with a hive (`HKLM`, `HKEY_LOCAL_MACHINE`, …, with or
/// without a trailing `:`), so that `reg.exe` never reads it as a switch or a
/// remote `\\machine\` form. The rest of the key is only quoted: a key name
/// may hold braces or parentheses. A double quote (or a typographic one) and a
/// control character are refused, as is a trailing backslash: Windows
/// `PowerShell` 5.1 does not escape them in the command line of a native
/// program, so they would split `reg.exe`'s arguments (the rest of the key
/// would become the export file, possibly a UNC path) or, before the closing
/// quote, swallow the next argument.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the key is invalid.
pub fn validate_registry_key(key: &str) -> Result<()> {
    let body = key.get(..10).map_or(key, |head| {
        if head.eq_ignore_ascii_case("Registry::") {
            key.get(10..).unwrap_or("")
        } else {
            key
        }
    });
    let (root, _) = body.split_once('\\').unwrap_or((body, ""));
    let root = root.strip_suffix(':').unwrap_or(root);
    if !REGISTRY_ROOTS.iter().any(|r| r.eq_ignore_ascii_case(root)) {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid registry key '{key}'. It must start with a hive \
                 (HKLM, HKCU, HKCR, HKU, HKCC or the HKEY_ name)."
            ),
        });
    }
    if key
        .chars()
        .any(|c| c.is_control() || matches!(c, '"' | '\u{201C}'..='\u{201E}'))
        || key.ends_with('\\')
    {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid registry key '{key}'. It must not contain a double quote or a \
                 control character, and must not end with a backslash."
            ),
        });
    }
    Ok(())
}

/// Validates a file path to prevent command injection.
///
/// Paths must contain only alphanumeric characters, backslashes, forward slashes,
/// colons, hyphens, underscores, spaces, and dots, and must not start with two
/// path separators (`\\host\share`, `//host/share`, `\/host`) once leading
/// whitespace is trimmed: a UNC path makes the Windows host open a connection
/// to `host`, with its own credentials. It must not start with `-` or end with
/// a separator: before the closing quote of an argument, a backslash escapes
/// that quote and swallows the next argument (`/y`) of `reg.exe`'s command line.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the path is invalid.
pub fn validate_file_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "File path cannot be empty".to_string(),
        });
    }
    let mut leading = path.trim_start().chars();
    if matches!(
        (leading.next(), leading.next()),
        (Some('\\' | '/'), Some('\\' | '/'))
    ) {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid file path '{path}'. A UNC path (two leading separators) is refused: \
                 the host would connect to a remote share."
            ),
        });
    }
    if path.chars().all(|c| {
        c.is_alphanumeric()
            || c == '\\'
            || c == '/'
            || c == ':'
            || c == '-'
            || c == '_'
            || c == ' '
            || c == '.'
    }) {
        if path.starts_with('-') || path.ends_with(['\\', '/']) {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "Invalid file path '{path}'. It must name a file: no leading '-' and no \
                     trailing separator."
                ),
            });
        }
        Ok(())
    } else {
        Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid file path '{path}'. \
                 Only alphanumeric, slash, backslash, colon, hyphen, underscore, space, \
                 and dot allowed.",
            ),
        })
    }
}

/// Builds `PowerShell` commands for Windows registry management.
pub struct WindowsRegistryCommandBuilder;

impl WindowsRegistryCommandBuilder {
    /// Build command to query a registry value.
    ///
    /// Constructs: `Get-ItemProperty -Path '{path}' [-Name '{name}']`
    #[must_use]
    pub fn query(path: &str, name: Option<&str>) -> String {
        let mut cmd = format!("Get-ItemProperty -Path {}", ps_escape(path));
        if let Some(n) = name {
            let _ = write!(cmd, " -Name {}", ps_escape(n));
        }
        cmd
    }

    /// Build command to set a registry value.
    ///
    /// The key is created first when it does not exist. `Set-ItemProperty`
    /// alone fails on a missing key — `Cannot find path '...' because it does
    /// not exist` — which made the tool unusable for anything but an existing
    /// key, and left `reg_export` and `reg_delete` with nothing to act on.
    /// `New-Item -Force` is idempotent on a key that is already there, and
    /// matches what `reg add` does.
    ///
    /// Constructs: `New-Item -Path '{path}' -Force | Out-Null;
    /// Set-ItemProperty -Path '{path}' -Name '{name}' -Value '{value}'
    /// [-Type {type}]`
    #[must_use]
    pub fn set_value(path: &str, name: &str, value: &str, value_type: Option<&str>) -> String {
        let mut cmd = format!(
            "New-Item -Path {} -Force | Out-Null; \
             Set-ItemProperty -Path {} -Name {} -Value {}",
            ps_escape(path),
            ps_escape(path),
            ps_escape(name),
            ps_escape(value),
        );
        if let Some(vt) = value_type {
            let _ = write!(cmd, " -Type {}", ps_escape(vt));
        }
        cmd
    }

    /// Build command to list registry subkeys.
    ///
    /// Constructs: `Get-ChildItem -Path '{path}'`
    #[must_use]
    pub fn list(path: &str) -> String {
        format!("Get-ChildItem -Path {}", ps_escape(path))
    }

    /// Build command to export a registry key to a file.
    ///
    /// Constructs: `reg export '{key}' '{file}' /y`
    #[must_use]
    pub fn export_key(key: &str, file: &str) -> String {
        let mut cmd = String::new();
        let _ = write!(cmd, "reg export {} {} /y", ps_escape(key), ps_escape(file));
        cmd
    }

    /// Build command to delete a registry property.
    ///
    /// Constructs: `Remove-ItemProperty -Path '{path}' -Name '{name}'`
    #[must_use]
    pub fn delete_property(path: &str, name: &str) -> String {
        let mut cmd = String::new();
        let _ = write!(
            cmd,
            "Remove-ItemProperty -Path {} -Name {}",
            ps_escape(path),
            ps_escape(name),
        );
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_registry_path ──────────────────────────────────────

    #[test]
    fn test_validate_registry_path_valid() {
        assert!(validate_registry_path(r"HKLM:\SOFTWARE\Microsoft").is_ok());
        assert!(validate_registry_path(r"HKCU:\Software\My App").is_ok());
        assert!(validate_registry_path(r"HKLM:\SYSTEM\CurrentControlSet").is_ok());
    }

    #[test]
    fn test_validate_registry_path_empty() {
        assert!(validate_registry_path("").is_err());
    }

    #[test]
    fn test_validate_registry_path_injection() {
        assert!(validate_registry_path(r"HKLM:\; whoami").is_err());
        assert!(validate_registry_path(r"HKLM:\$(hostname)").is_err());
        assert!(validate_registry_path(r"HKLM:\|Out-File").is_err());
    }

    /// F56: a UNC or file system path must not reach `Get-ItemProperty`.
    #[test]
    fn test_validate_registry_path_requires_a_registry_provider() {
        for path in [
            r"\\attacker.example\share\x",
            r"C:\Windows",
            "relative",
            r"\Registry\x",
            r"HKLMx:\x",
        ] {
            let err = validate_registry_path(path).expect_err(path);
            assert!(err.to_string().contains("registry drive"), "{path}: {err}");
        }
        for path in [
            r"HKLM:\SOFTWARE",
            r"hkcu:\Software\x",
            r"HKU:\S-1-5-18",
            r"HKCC:",
            r"Registry::HKEY_LOCAL_MACHINE\SOFTWARE",
            r"Registry::HKLM\SOFTWARE",
        ] {
            validate_registry_path(path).expect(path);
        }
    }

    #[test]
    fn test_validate_registry_key_requires_a_hive() {
        for key in [
            r"\\attacker\share",
            "/y",
            "-x",
            r"C:\x",
            "x",
            r"HKLMX\a",
            "",
        ] {
            assert!(validate_registry_key(key).is_err(), "{key}");
        }
        for key in [
            r"HKLM\SOFTWARE\MyApp",
            r"HKEY_CURRENT_USER\Software",
            r"HKLM:\SOFTWARE",
            "HKCR",
            r"Registry::HKCU\x",
        ] {
            validate_registry_key(key).expect(key);
        }
        validate_registry_key(r"HKLM\SOFTWARE\Classes\CLSID\{0000-1} (x86)").unwrap();
    }

    /// A `"` in the key splits `reg.exe`'s arguments under Windows `PowerShell`
    /// 5.1, which does not escape it: the rest of the key becomes the file.
    #[test]
    fn test_validate_registry_key_refuses_quotes_controls_and_trailing_backslash() {
        for key in [
            "HKLM\\SOFTWARE\" \\\\attacker\\share\\loot\" x\"z",
            "HKLM\\SOFTWARE\"",
            "\"HKLM\\SOFTWARE\"",
            "HKLM\\SOFTWARE\u{201C}x",
            "HKLM\\SOFTWARE\u{201E}x",
            "HKLM\\SOFTWARE\nx",
            "HKLM\\SOFTWARE\u{0}x",
            "HKLM\\SOFTWARE\\My App\\",
            "HKLM\\",
        ] {
            assert!(validate_registry_key(key).is_err(), "{key:?}");
        }
        for key in [
            r"HKLM\SOFTWARE\My App",
            r"HKCU\Software\{0000-1} (x86)",
            r"HKLM:\SOFTWARE\Vendor's",
        ] {
            validate_registry_key(key).expect(key);
        }
    }

    // ── validate_registry_name ──────────────────────────────────────

    #[test]
    fn test_validate_registry_name_valid() {
        assert!(validate_registry_name("DisplayName").is_ok());
        assert!(validate_registry_name("Install-Path").is_ok());
        assert!(validate_registry_name("my_value").is_ok());
        assert!(validate_registry_name("value.v2").is_ok());
    }

    #[test]
    fn test_validate_registry_name_empty() {
        assert!(validate_registry_name("").is_err());
    }

    #[test]
    fn test_validate_registry_name_injection() {
        assert!(validate_registry_name("name; whoami").is_err());
        assert!(validate_registry_name("name$(hostname)").is_err());
        assert!(validate_registry_name("name|Out-File").is_err());
    }

    // ── validate_file_path ──────────────────────────────────────────

    #[test]
    fn test_validate_file_path_valid() {
        assert!(validate_file_path(r"C:\backup.reg").is_ok());
        assert!(validate_file_path(r"C:\Users\admin\export.reg").is_ok());
        assert!(validate_file_path("/tmp/export.reg").is_ok());
    }

    /// F56: `reg export` must not write the export to a remote share.
    #[test]
    fn test_validate_file_path_refuses_unc() {
        for path in [
            r"\\attacker.example\share\loot.reg",
            "//attacker.example/share/loot.reg",
            r"\/attacker\share",
            r"/\attacker\share",
        ] {
            let err = validate_file_path(path).expect_err(path);
            assert!(err.to_string().contains("UNC"), "{path}: {err}");
        }
        assert!(validate_file_path(r"\Windows\Temp\x.reg").is_ok());
        assert!(validate_file_path("x.reg").is_ok());
    }

    /// A UNC path hidden behind leading whitespace, a `"`, a leading switch
    /// character or a trailing separator (which escapes the closing quote under
    /// Windows `PowerShell` 5.1) is refused; plain paths still pass.
    #[test]
    fn test_validate_file_path_refuses_hidden_unc_and_argument_splitting() {
        for path in [
            " \\\\attacker\\share\\x.reg",
            "\t//attacker/share/x.reg",
            "\"\\\\attacker\\share\\x.reg\"",
            "C:\\x\".reg",
            "-x.reg",
            "C:\\My Dir\\",
            "C:/dir/",
        ] {
            assert!(validate_file_path(path).is_err(), "{path:?}");
        }
        for path in [r"C:\My Dir\x.reg", "C:/dir/x.reg", "x-y.reg"] {
            validate_file_path(path).expect(path);
        }
    }

    #[test]
    fn test_validate_file_path_empty() {
        assert!(validate_file_path("").is_err());
    }

    #[test]
    fn test_validate_file_path_injection() {
        assert!(validate_file_path("file; whoami").is_err());
        assert!(validate_file_path("file$(hostname)").is_err());
        assert!(validate_file_path("file|Out-File").is_err());
    }

    // ── query ───────────────────────────────────────────────────────

    #[test]
    fn test_query_without_name() {
        let cmd = WindowsRegistryCommandBuilder::query(r"HKLM:\SOFTWARE\Microsoft", None);
        assert_eq!(cmd, r"Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft'");
    }

    #[test]
    fn test_query_with_name() {
        let cmd =
            WindowsRegistryCommandBuilder::query(r"HKLM:\SOFTWARE\Microsoft", Some("DisplayName"));
        assert_eq!(
            cmd,
            r"Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft' -Name 'DisplayName'"
        );
    }

    #[test]
    fn test_query_injection_in_path() {
        let cmd = WindowsRegistryCommandBuilder::query(r"HKLM:\; whoami", None);
        assert!(cmd.contains(r"'HKLM:\; whoami'"));
    }

    #[test]
    fn test_query_injection_in_name() {
        let cmd = WindowsRegistryCommandBuilder::query(r"HKLM:\SOFTWARE", Some("name$(hostname)"));
        assert!(cmd.contains("'name$(hostname)'"));
    }

    #[test]
    fn test_query_single_quote_in_path() {
        let cmd = WindowsRegistryCommandBuilder::query(r"HKLM:\it's", None);
        assert!(cmd.contains(r"'HKLM:\it''s'"));
    }

    // ── set_value ───────────────────────────────────────────────────

    #[test]
    fn test_set_value_without_type() {
        let cmd = WindowsRegistryCommandBuilder::set_value(
            r"HKLM:\SOFTWARE\MyApp",
            "Setting",
            "enabled",
            None,
        );
        assert_eq!(
            cmd,
            r"New-Item -Path 'HKLM:\SOFTWARE\MyApp' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\SOFTWARE\MyApp' -Name 'Setting' -Value 'enabled'"
        );
    }

    /// `Set-ItemProperty` cannot create a missing key, so the key has to be
    /// made first or the whole set/export/delete chain has nothing to act on.
    #[test]
    fn test_set_value_creates_the_key_first() {
        let cmd = WindowsRegistryCommandBuilder::set_value(
            r"HKLM:\SOFTWARE\New\Key",
            "Setting",
            "1",
            None,
        );
        assert!(
            cmd.starts_with(r"New-Item -Path 'HKLM:\SOFTWARE\New\Key' -Force"),
            "the key must be created before the property is set, got: {cmd}"
        );
    }

    #[test]
    fn test_set_value_with_type() {
        let cmd = WindowsRegistryCommandBuilder::set_value(
            r"HKLM:\SOFTWARE\MyApp",
            "Count",
            "42",
            Some("DWord"),
        );
        assert!(cmd.contains("-Type 'DWord'"));
    }

    #[test]
    fn test_set_value_injection_in_value() {
        let cmd =
            WindowsRegistryCommandBuilder::set_value(r"HKLM:\SOFTWARE", "key", "val; whoami", None);
        assert!(cmd.contains("'val; whoami'"));
    }

    #[test]
    fn test_set_value_injection_in_type() {
        let cmd = WindowsRegistryCommandBuilder::set_value(
            r"HKLM:\SOFTWARE",
            "key",
            "val",
            Some("DWord; whoami"),
        );
        assert!(cmd.contains("'DWord; whoami'"));
    }

    // ── list ────────────────────────────────────────────────────────

    #[test]
    fn test_list() {
        let cmd = WindowsRegistryCommandBuilder::list(r"HKLM:\SOFTWARE");
        assert_eq!(cmd, r"Get-ChildItem -Path 'HKLM:\SOFTWARE'");
    }

    #[test]
    fn test_list_injection() {
        let cmd = WindowsRegistryCommandBuilder::list(r"HKLM:\; Remove-Item C:\");
        assert!(cmd.contains(r"'HKLM:\; Remove-Item C:\'"));
    }

    // ── export_key ──────────────────────────────────────────────────

    #[test]
    fn test_export_key() {
        let cmd =
            WindowsRegistryCommandBuilder::export_key(r"HKLM\SOFTWARE\MyApp", r"C:\backup.reg");
        assert_eq!(cmd, r"reg export 'HKLM\SOFTWARE\MyApp' 'C:\backup.reg' /y");
    }

    #[test]
    fn test_export_key_injection_in_key() {
        let cmd = WindowsRegistryCommandBuilder::export_key(r"HKLM\; whoami", r"C:\backup.reg");
        assert!(cmd.contains(r"'HKLM\; whoami'"));
    }

    #[test]
    fn test_export_key_injection_in_file() {
        let cmd =
            WindowsRegistryCommandBuilder::export_key(r"HKLM\SOFTWARE", r"C:\file$(hostname)");
        assert!(cmd.contains(r"'C:\file$(hostname)'"));
    }

    // ── delete_property ─────────────────────────────────────────────

    #[test]
    fn test_delete_property() {
        let cmd =
            WindowsRegistryCommandBuilder::delete_property(r"HKLM:\SOFTWARE\MyApp", "OldSetting");
        assert_eq!(
            cmd,
            r"Remove-ItemProperty -Path 'HKLM:\SOFTWARE\MyApp' -Name 'OldSetting'"
        );
    }

    #[test]
    fn test_delete_property_injection_in_path() {
        let cmd = WindowsRegistryCommandBuilder::delete_property(r"HKLM:\; whoami", "key");
        assert!(cmd.contains(r"'HKLM:\; whoami'"));
    }

    #[test]
    fn test_delete_property_injection_in_name() {
        let cmd = WindowsRegistryCommandBuilder::delete_property(r"HKLM:\SOFTWARE", "key|Out-File");
        assert!(cmd.contains("'key|Out-File'"));
    }

    #[test]
    fn test_delete_property_single_quote_in_name() {
        let cmd = WindowsRegistryCommandBuilder::delete_property(r"HKLM:\SOFTWARE", "it's a key");
        assert!(cmd.contains("'it''s a key'"));
    }

    // ── Shell Injection Prevention ──────────────────────────────────

    #[test]
    fn test_dollar_variable_neutralized() {
        let cmd = WindowsRegistryCommandBuilder::query("$env:COMPUTERNAME", None);
        assert!(cmd.contains("'$env:COMPUTERNAME'"));
    }

    #[test]
    fn test_backtick_neutralized() {
        let cmd = WindowsRegistryCommandBuilder::list(r"HKLM:\`whoami`");
        assert!(cmd.contains(r"'HKLM:\`whoami`'"));
    }

    #[test]
    fn test_pipe_neutralized() {
        let cmd = WindowsRegistryCommandBuilder::query(r"HKLM:\|Out-File", None);
        assert!(cmd.contains(r"'HKLM:\|Out-File'"));
    }
}
