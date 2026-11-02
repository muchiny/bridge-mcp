//! Shell-aware utilities for cross-platform SSH command construction.
//!
//! Provides escaping, command composition, and detection helpers that
//! adapt to the remote host's shell type (POSIX, `cmd.exe`, `PowerShell`).

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

/// Escape a string for safe interpolation into a shell command.
///
/// - **Posix**: wraps in single quotes, escapes internal `'` with `'\''`.
/// - **Cmd**: legacy caret form, kept for API compatibility. It cannot quote `%` and
///   corrupts `&` and `^` inside quotes; new code uses [`try_escape`].
/// - **`PowerShell`**: wraps in `'`; each of U+0027, U+2018, U+2019, U+201A and
///   U+201B is doubled, as PowerShell's `CodeGeneration.EscapeSingleQuotedStringContent`
///   does (any of the five ends a verbatim string).
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
        ShellType::PowerShell => format!("'{}'", escape_ps_single_quoted_content(s)),
    }
}

/// The single-quote characters of the Windows PowerShell Language
/// Specification 3.0, section 2.3.5.2. Any of them opens or closes a verbatim
/// string.
pub const PS_SINGLE_QUOTES: [char; 5] =
    ['\u{0027}', '\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}'];

/// Escape text for the inside of a `PowerShell` verbatim (single-quoted)
/// string, without adding the outer quotes.
///
/// Every character of `s` is emitted, and a second time when it is one of
/// [`PS_SINGLE_QUOTES`]. This is what
/// `CodeGeneration.EscapeSingleQuotedStringContent` does: U+201C to U+201E
/// are left alone.
///
/// # Examples
///
/// ```
/// use bridge_mcp::domain::use_cases::shell::escape_ps_single_quoted_content;
///
/// assert_eq!(escape_ps_single_quoted_content("it\u{2019}s"), "it\u{2019}\u{2019}s");
/// ```
#[must_use]
pub fn escape_ps_single_quoted_content(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        out.push(c);
        if PS_SINGLE_QUOTES.contains(&c) {
            out.push(c);
        }
    }
    out
}

/// Whether `cmd.exe` cannot hold `c` inert inside double quotes.
///
/// `"` ends the quoted run, `%` and `!` expand, and a control character ends
/// the line. `$`, the backtick and the three PowerShell double-quote
/// characters mean nothing to `cmd.exe`: they are refused so that a value
/// quoted for `cmd.exe` stays inert even when the host's real shell is
/// PowerShell (the declared shell can be wrong).
const fn cmd_cannot_quote(c: char) -> bool {
    matches!(
        c,
        '"' | '%' | '!' | '$' | '`' | '\u{201C}'..='\u{201E}' | '\u{0}'..='\u{1F}' | '\u{7F}'
    )
}

/// Quote `s` for the given shell, or refuse when the shell cannot quote it.
///
/// - **Posix** and **`PowerShell`**: the same as [`escape`]; every string can be
///   quoted.
/// - **Cmd**: wraps in double quotes with no caret and no `%%`, the only form
///   `cmd.exe` reads literally for `& | < > ^ ( )`. The characters it cannot
///   quote are refused: `"`, `%`, `!`, control characters (U+0000 to U+001F
///   and U+007F), `$`, the backtick, and U+201C to U+201E.
///
/// # Errors
///
/// [`BridgeError::CommandDenied`] on the first character `cmd.exe` cannot
/// quote.
///
/// # Examples
///
/// ```
/// use bridge_mcp::config::ShellType;
/// use bridge_mcp::domain::use_cases::shell;
///
/// assert_eq!(shell::try_escape("C:\\a&b", ShellType::Cmd).unwrap(), "\"C:\\a&b\"");
/// assert!(shell::try_escape("%OS%", ShellType::Cmd).is_err());
/// ```
pub fn try_escape(s: &str, shell: ShellType) -> Result<String> {
    match shell {
        ShellType::Posix | ShellType::PowerShell => Ok(escape(s, shell)),
        ShellType::Cmd => {
            if let Some(c) = s.chars().find(|&c| cmd_cannot_quote(c)) {
                return Err(BridgeError::CommandDenied {
                    reason: format!(
                        "cannot quote {c:?} (U+{:04X}) for cmd.exe; if the host's real shell is PowerShell (OpenSSH DefaultShell, WinRM, PSRP), set `shell: powershell` for it, otherwise change directory inside the command",
                        u32::from(c)
                    ),
                });
            }
            Ok(format!("\"{s}\""))
        }
    }
}

/// Build a "change directory then run command" one-liner, refusing a directory
/// the shell cannot quote.
///
/// - **Posix**: `cd '/path' && command`
/// - **Cmd**: `cd /d "C:\path" && command`
/// - **`PowerShell`**: `Set-Location -LiteralPath 'C:\path' -ErrorAction Stop; command`
///
/// Every form runs `command` only once the directory change succeeded: `&&`
/// for Posix and Cmd, `-ErrorAction Stop` for `PowerShell`, where a missing
/// directory is otherwise a non-terminating error and `command` would run in
/// the default directory.
///
/// # Errors
///
/// [`BridgeError::CommandDenied`] when `dir` holds a character [`try_escape`]
/// refuses for `shell`.
///
/// # Examples
///
/// ```
/// use bridge_mcp::config::ShellType;
/// use bridge_mcp::domain::use_cases::shell;
///
/// assert_eq!(
///     shell::try_cd_and_run("/var/log", "ls", ShellType::Posix).unwrap(),
///     "cd '/var/log' && ls"
/// );
/// ```
pub fn try_cd_and_run(dir: &str, cmd: &str, shell: ShellType) -> Result<String> {
    let q = try_escape(dir, shell)?;
    Ok(match shell {
        ShellType::Posix => format!("cd {q} && {cmd}"),
        ShellType::Cmd => format!("cd /d {q} && {cmd}"),
        ShellType::PowerShell => format!("Set-Location -LiteralPath {q} -ErrorAction Stop; {cmd}"),
    })
}

/// Build a "change directory then run command" one-liner.
///
/// Legacy form: the Cmd arm goes through the caret form of [`escape`], which
/// cannot quote every directory. New code uses [`try_cd_and_run`].
///
/// - **Posix**: `cd '/path' && command`
/// - **Cmd**: `cd /d "C:\path" && command`
/// - **`PowerShell`**: `Set-Location 'C:\path'; command`
#[deprecated(
    since = "5.0.0",
    note = "use try_cd_and_run: the cmd form cannot quote every directory"
)]
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

    #[test]
    fn ps_single_quotes_are_the_five_of_the_grammar() {
        assert_eq!(
            PS_SINGLE_QUOTES,
            ['\u{0027}', '\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}']
        );
    }

    #[test]
    fn powershell_escape_doubles_every_single_quote_character() {
        for q in PS_SINGLE_QUOTES {
            assert_eq!(
                escape(&format!("a{q}b"), ShellType::PowerShell),
                format!("'a{q}{q}b'"),
                "U+{:04X}",
                u32::from(q)
            );
        }
    }

    #[test]
    fn powershell_escape_mixed_quotes_at_both_ends() {
        assert_eq!(
            escape("'\u{2019}x\u{2018}\u{201A}\u{201B}'", ShellType::PowerShell),
            "'''\u{2019}\u{2019}x\u{2018}\u{2018}\u{201A}\u{201A}\u{201B}\u{201B}'''"
        );
    }

    #[test]
    fn powershell_escape_leaves_double_quote_characters_alone() {
        let s = "a\"\u{201C}\u{201D}\u{201E}b";
        assert_eq!(escape(s, ShellType::PowerShell), format!("'{s}'"));
    }

    #[test]
    fn powershell_escape_hostile_value_stays_one_literal() {
        assert_eq!(
            escape(
                "a\u{2019}; Write-Output pwned; \u{2019}",
                ShellType::PowerShell
            ),
            "'a\u{2019}\u{2019}; Write-Output pwned; \u{2019}\u{2019}'"
        );
    }

    #[test]
    fn powershell_escape_edge_values() {
        assert_eq!(escape("", ShellType::PowerShell), "''");
        assert_eq!(escape("a'", ShellType::PowerShell), "'a'''");
        assert_eq!(
            escape("\u{201B}\u{201B}\u{201B}", ShellType::PowerShell),
            "'\u{201B}\u{201B}\u{201B}\u{201B}\u{201B}\u{201B}'"
        );
        assert_eq!(
            escape("\u{2018}", ShellType::PowerShell),
            "'\u{2018}\u{2018}'"
        );
        assert_eq!(
            escape("\u{201A}", ShellType::PowerShell),
            "'\u{201A}\u{201A}'"
        );
        assert_eq!(
            escape("\u{201B}", ShellType::PowerShell),
            "'\u{201B}\u{201B}'"
        );
    }

    #[test]
    fn powershell_escape_keeps_other_characters_as_they_are() {
        assert_eq!(escape("a`b", ShellType::PowerShell), "'a`b'");
        assert_eq!(escape("a\nb", ShellType::PowerShell), "'a\nb'");
        assert_eq!(escape("\u{1F600}", ShellType::PowerShell), "'\u{1F600}'");
        assert_eq!(
            escape("\u{1F600}\u{2019}", ShellType::PowerShell),
            "'\u{1F600}\u{2019}\u{2019}'"
        );
    }

    #[test]
    fn escape_ps_single_quoted_content_adds_no_outer_quotes() {
        assert_eq!(
            escape_ps_single_quoted_content("it\u{2019}s"),
            "it\u{2019}\u{2019}s"
        );
        assert_eq!(escape_ps_single_quoted_content(""), "");
    }

    // ===== cd_and_run =====

    #[test]
    #[expect(
        deprecated,
        reason = "the legacy form stays pinned until it is removed"
    )]
    fn test_cd_and_run_posix() {
        assert_eq!(
            cd_and_run("/var/log", "ls -la", ShellType::Posix),
            "cd '/var/log' && ls -la"
        );
    }

    #[test]
    #[expect(
        deprecated,
        reason = "the legacy form stays pinned until it is removed"
    )]
    fn test_cd_and_run_cmd() {
        assert_eq!(
            cd_and_run("C:\\Users", "dir", ShellType::Cmd),
            "cd /d \"C:\\Users\" && dir"
        );
    }

    #[test]
    #[expect(
        deprecated,
        reason = "the legacy form stays pinned until it is removed"
    )]
    fn test_cd_and_run_powershell() {
        assert_eq!(
            cd_and_run("C:\\Users", "Get-ChildItem", ShellType::PowerShell),
            "Set-Location 'C:\\Users'; Get-ChildItem"
        );
    }

    // ===== try_escape / try_cd_and_run =====

    #[test]
    fn cmd_try_escape_specials_literal_inside_quotes() {
        assert_eq!(
            try_escape("C:\\a&b|c<d>e^f(g)", ShellType::Cmd).unwrap(),
            "\"C:\\a&b|c<d>e^f(g)\""
        );
    }

    #[test]
    fn cmd_try_escape_refuses_each_char() {
        for c in [
            '"', '%', '!', '\0', '\t', '\r', '\n', '\u{1F}', '\u{7F}', '$', '`', '\u{201C}',
            '\u{201D}', '\u{201E}',
        ] {
            let err = try_escape(&format!("C:\\a{c}b"), ShellType::Cmd).unwrap_err();
            let needle = format!("U+{:04X}", u32::from(c));
            assert!(
                matches!(&err, BridgeError::CommandDenied { reason } if reason.contains(&needle)),
                "{needle}: {err:?}"
            );
        }
    }

    #[test]
    fn try_escape_posix_and_powershell_match_escape() {
        for s in ["it's", "a\u{2019}b", "%PATH%"] {
            assert_eq!(
                try_escape(s, ShellType::Posix).unwrap(),
                escape(s, ShellType::Posix)
            );
            assert_eq!(
                try_escape(s, ShellType::PowerShell).unwrap(),
                escape(s, ShellType::PowerShell)
            );
        }
    }

    #[test]
    fn try_cd_and_run_cmd_quotes_without_carets() {
        assert_eq!(
            try_cd_and_run("C:\\a&b^c", "dir", ShellType::Cmd).unwrap(),
            "cd /d \"C:\\a&b^c\" && dir"
        );
    }

    #[test]
    fn try_cd_and_run_powershell_uses_literal_path() {
        assert_eq!(
            try_cd_and_run("C:\\[x]*", "Get-ChildItem", ShellType::PowerShell).unwrap(),
            "Set-Location -LiteralPath 'C:\\[x]*' -ErrorAction Stop; Get-ChildItem"
        );
    }

    #[test]
    fn try_cd_and_run_posix_is_unchanged() {
        assert_eq!(
            try_cd_and_run("/var/log", "ls -la", ShellType::Posix).unwrap(),
            "cd '/var/log' && ls -la"
        );
    }

    #[test]
    fn try_cd_and_run_refuses_before_building_a_cmd_line() {
        assert!(try_cd_and_run("C:\\%OS%", "dir", ShellType::Cmd).is_err());
    }

    proptest::proptest! {
        #[test]
        fn cmd_try_escape_output_is_inert(s in proptest::prelude::any::<String>()) {
            // Independent statement of the refused set.
            let refused = |c: char| matches!(c, '"' | '%' | '!' | '$' | '`' | '\u{201C}'..='\u{201E}' | '\u{0}'..='\u{1F}' | '\u{7F}');
            match try_escape(&s, ShellType::Cmd) {
                Ok(q) => {
                    proptest::prop_assert_eq!(q, format!("\"{s}\""));
                    proptest::prop_assert!(!s.chars().any(refused));
                }
                Err(_) => proptest::prop_assert!(s.chars().any(refused)),
            }
        }
    }

    /// Every `.rs` file under `dir`, recursively.
    fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read_dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    #[test]
    fn no_production_code_escapes_for_cmd() {
        // `shell.rs` holds the function and its own tests, and `utils.rs` its
        // wrapper; no other line may reach the legacy cmd form.
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rust_files(&src, &mut files);
        assert!(files.len() > 100, "the walk found {} files", files.len());
        for path in files {
            let rel = path.strip_prefix(&src).expect("under src");
            if rel == std::path::Path::new("domain/use_cases/shell.rs")
                || rel == std::path::Path::new("mcp/tool_handlers/utils.rs")
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read source");
            for (i, line) in text.lines().enumerate() {
                assert!(
                    !(line.contains("escape(") && line.contains("ShellType::Cmd")),
                    "{}:{}: {line}",
                    path.display(),
                    i + 1
                );
            }
        }
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
    #[expect(
        deprecated,
        reason = "the legacy form stays pinned until it is removed"
    )]
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
