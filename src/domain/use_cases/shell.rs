//! Shell-aware utilities for cross-platform SSH command construction.
//!
//! Provides escaping, command composition, and detection helpers that
//! adapt to the remote host's shell type (POSIX, `cmd.exe`, `PowerShell`).

use crate::config::ShellType;

/// Escape a string for safe interpolation into a shell command.
///
/// - **Posix**: wraps in single quotes, escapes internal `'` with `'\''`.
/// - **Cmd**: wraps in double quotes, escapes `& | < > ^` with caret `^`.
/// - **`PowerShell`**: wraps in single quotes, doubles internal `'`.
///
/// # Examples
///
/// ```
/// use bridge_mcp::config::ShellType;
/// use bridge_mcp::domain::use_cases::shell;
///
/// assert_eq!(shell::escape("hello", ShellType::Posix), "'hello'");
/// assert_eq!(shell::escape("it's", ShellType::Posix), "'it'\\''s'");
/// assert_eq!(shell::escape("a&b", ShellType::Cmd), "\"a^&b\"");
/// assert_eq!(shell::escape("it's", ShellType::PowerShell), "'it''s'");
/// ```
#[must_use]
pub fn escape(s: &str, shell: ShellType) -> String {
    match shell {
        ShellType::Posix => format!("'{}'", s.replace('\'', "'\\''")),
        ShellType::Cmd => {
            let escaped = s
                .replace('^', "^^")
                .replace('%', "%%")
                .replace('&', "^&")
                .replace('|', "^|")
                .replace('<', "^<")
                .replace('>', "^>")
                .replace('"', "^\"");
            format!("\"{escaped}\"")
        }
        ShellType::PowerShell => format!("'{}'", s.replace('\'', "''")),
    }
}

/// Build a "change directory then run command" one-liner.
///
/// - **Posix**: `cd '/path' && command`
/// - **Cmd**: `cd /d "C:\path" && command`
/// - **`PowerShell`**: `Set-Location 'C:\path'; command`
///
/// # Examples
///
/// ```
/// use bridge_mcp::config::ShellType;
/// use bridge_mcp::domain::use_cases::shell;
///
/// assert_eq!(
///     shell::cd_and_run("/var/log", "ls", ShellType::Posix),
///     "cd '/var/log' && ls"
/// );
/// ```
#[must_use]
pub fn cd_and_run(dir: &str, cmd: &str, shell: ShellType) -> String {
    match shell {
        ShellType::Posix => format!("cd {} && {cmd}", escape(dir, shell)),
        ShellType::Cmd => format!("cd /d {} && {cmd}", escape(dir, shell)),
        ShellType::PowerShell => format!("Set-Location {}; {cmd}", escape(dir, shell)),
    }
}

/// Build a command that checks whether an executable exists.
///
/// - **Posix**: `command -v name`
/// - **Cmd**: `where name`
/// - **`PowerShell`**: `Get-Command name -ErrorAction SilentlyContinue`
#[must_use]
pub fn command_exists(name: &str, shell: ShellType) -> String {
    match shell {
        ShellType::Posix => format!("command -v {}", escape(name, shell)),
        ShellType::Cmd => format!("where {name}"),
        ShellType::PowerShell => {
            format!("Get-Command {name} -ErrorAction SilentlyContinue")
        }
    }
}

/// Return the null device path for the given shell.
///
/// - **Posix**: `/dev/null`
/// - **Cmd**: `NUL`
/// - **`PowerShell`**: `$null`
#[must_use]
pub const fn null_device(shell: ShellType) -> &'static str {
    match shell {
        ShellType::Posix => "/dev/null",
        ShellType::Cmd => "NUL",
        ShellType::PowerShell => "$null",
    }
}

/// Optionally wrap a command with `sudo` (POSIX only).
///
/// On Windows shells, `sudo` does not exist; the command is returned as-is.
#[must_use]
pub fn elevate(cmd: &str, shell: ShellType) -> String {
    match shell {
        ShellType::Posix => format!("sudo {cmd}"),
        ShellType::Cmd | ShellType::PowerShell => cmd.to_string(),
    }
}

/// Return the stderr-to-null redirect suffix for the given shell.
///
/// - **Posix**: `2>/dev/null`
/// - **Cmd**: `2>NUL`
/// - **`PowerShell`**: `2>$null`
#[must_use]
pub const fn stderr_to_null(shell: ShellType) -> &'static str {
    match shell {
        ShellType::Posix => "2>/dev/null",
        ShellType::Cmd => "2>NUL",
        ShellType::PowerShell => "2>$null",
    }
}

/// Return the exit-code variable for the given shell.
///
/// - **Posix**: `$?`
/// - **Cmd**: `%ERRORLEVEL%`
/// - **`PowerShell`**: `$LASTEXITCODE`
#[must_use]
pub const fn exit_code_var(shell: ShellType) -> &'static str {
    match shell {
        ShellType::Posix => "$?",
        ShellType::Cmd => "%ERRORLEVEL%",
        ShellType::PowerShell => "$LASTEXITCODE",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== escape =====

    #[test]
    fn test_posix_escape_simple() {
        assert_eq!(escape("hello", ShellType::Posix), "'hello'");
    }

    #[test]
    fn test_posix_escape_with_single_quote() {
        assert_eq!(escape("it's", ShellType::Posix), "'it'\\''s'");
    }

    #[test]
    fn test_cmd_escape_simple() {
        assert_eq!(escape("hello", ShellType::Cmd), "\"hello\"");
    }

    #[test]
    fn test_cmd_escape_special_chars() {
        assert_eq!(escape("a&b|c", ShellType::Cmd), "\"a^&b^|c\"");
    }

    #[test]
    fn test_cmd_escape_double_quote() {
        assert_eq!(escape("say \"hi\"", ShellType::Cmd), "\"say ^\"hi^\"\"");
    }

    #[test]
    fn test_cmd_escape_caret() {
        assert_eq!(escape("a^b", ShellType::Cmd), "\"a^^b\"");
    }

    #[test]
    fn test_cmd_escape_angle_brackets() {
        assert_eq!(escape("a<b>c", ShellType::Cmd), "\"a^<b^>c\"");
    }

    #[test]
    fn test_cmd_escape_percent_sign() {
        assert_eq!(escape("%TEMP%", ShellType::Cmd), "\"%%TEMP%%\"");
    }

    #[test]
    fn test_cmd_escape_percent_in_path() {
        assert_eq!(escape("%PATH%\\evil", ShellType::Cmd), "\"%%PATH%%\\evil\"");
    }

    #[test]
    fn test_powershell_escape_simple() {
        assert_eq!(escape("hello", ShellType::PowerShell), "'hello'");
    }

    #[test]
    fn test_powershell_escape_with_single_quote() {
        assert_eq!(escape("it's", ShellType::PowerShell), "'it''s'");
    }

    // ===== cd_and_run =====

    #[test]
    fn test_cd_and_run_posix() {
        assert_eq!(
            cd_and_run("/var/log", "ls -la", ShellType::Posix),
            "cd '/var/log' && ls -la"
        );
    }

    #[test]
    fn test_cd_and_run_cmd() {
        assert_eq!(
            cd_and_run("C:\\Users", "dir", ShellType::Cmd),
            "cd /d \"C:\\Users\" && dir"
        );
    }

    #[test]
    fn test_cd_and_run_powershell() {
        assert_eq!(
            cd_and_run("C:\\Users", "Get-ChildItem", ShellType::PowerShell),
            "Set-Location 'C:\\Users'; Get-ChildItem"
        );
    }

    // ===== command_exists =====

    #[test]
    fn test_command_exists_posix() {
        assert_eq!(
            command_exists("docker", ShellType::Posix),
            "command -v 'docker'"
        );
    }

    #[test]
    fn test_command_exists_cmd() {
        assert_eq!(command_exists("docker", ShellType::Cmd), "where docker");
    }

    #[test]
    fn test_command_exists_powershell() {
        assert_eq!(
            command_exists("docker", ShellType::PowerShell),
            "Get-Command docker -ErrorAction SilentlyContinue"
        );
    }

    // ===== null_device =====

    #[test]
    fn test_null_device() {
        assert_eq!(null_device(ShellType::Posix), "/dev/null");
        assert_eq!(null_device(ShellType::Cmd), "NUL");
        assert_eq!(null_device(ShellType::PowerShell), "$null");
    }

    // ===== elevate =====

    #[test]
    fn test_elevate_posix() {
        assert_eq!(
            elevate("systemctl restart nginx", ShellType::Posix),
            "sudo systemctl restart nginx"
        );
    }

    #[test]
    fn test_elevate_windows() {
        assert_eq!(elevate("net start", ShellType::Cmd), "net start");
        assert_eq!(
            elevate("Restart-Service", ShellType::PowerShell),
            "Restart-Service"
        );
    }

    // ===== stderr_to_null =====

    #[test]
    fn test_stderr_to_null() {
        assert_eq!(stderr_to_null(ShellType::Posix), "2>/dev/null");
        assert_eq!(stderr_to_null(ShellType::Cmd), "2>NUL");
        assert_eq!(stderr_to_null(ShellType::PowerShell), "2>$null");
    }

    // ===== exit_code_var =====

    #[test]
    fn test_exit_code_var() {
        assert_eq!(exit_code_var(ShellType::Posix), "$?");
        assert_eq!(exit_code_var(ShellType::Cmd), "%ERRORLEVEL%");
        assert_eq!(exit_code_var(ShellType::PowerShell), "$LASTEXITCODE");
    }

    // ===== Edge Cases =====

    #[test]
    fn test_escape_multibyte_utf8() {
        let emoji = escape("hello 🎉 world", ShellType::Posix);
        assert_eq!(emoji, "'hello 🎉 world'");

        let cjk = escape("日本語テスト", ShellType::PowerShell);
        assert_eq!(cjk, "'日本語テスト'");

        let mixed = escape("café résumé naïve", ShellType::Cmd);
        assert!(mixed.starts_with('"'));
        assert!(mixed.ends_with('"'));
        assert!(mixed.contains("café résumé naïve"));
    }

    #[test]
    fn test_escape_very_long_string() {
        let long = "x".repeat(10_000);
        let escaped = escape(&long, ShellType::Posix);
        assert_eq!(escaped.len(), 10_002); // 10_000 + 2 quotes
        assert!(escaped.starts_with('\''));
        assert!(escaped.ends_with('\''));
    }

    #[test]
    fn test_cd_and_run_with_relative_path() {
        let cmd = cd_and_run("./subdir", "ls", ShellType::Posix);
        assert_eq!(cmd, "cd './subdir' && ls");

        let cmd2 = cd_and_run("../parent", "pwd", ShellType::Posix);
        assert_eq!(cmd2, "cd '../parent' && pwd");

        let cmd3 = cd_and_run(".\\subdir", "dir", ShellType::Cmd);
        assert!(cmd3.starts_with("cd /d"));
        assert!(cmd3.contains(".\\subdir"));
    }
}
