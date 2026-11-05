//! File Operations Command Builder
//!
//! Builds commands for file read, write, permissions, and stat operations.

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

use super::shell::refuse_option_like;

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Quote a path that follows the mode or owner operand of `chmod`/`chown`.
///
/// Those two take their first operand without an option before it, so `--`
/// cannot be placed ahead of the path on every `getopt`. A path starting with
/// `-` is made relative instead (`./-x` names the same file).
fn path_operand(path: &str) -> String {
    if path.starts_with('-') {
        shell_escape(&format!("./{path}"))
    } else {
        shell_escape(path)
    }
}

/// Validate a `chmod` mode: an octal number of up to four digits, or a
/// symbolic mode (`u+x`, `go-w,a+r`, `-x`).
fn validate_chmod_mode(mode: &str) -> Result<()> {
    let octal = !mode.is_empty() && mode.len() <= 4 && mode.chars().all(|c| c.is_digit(8));
    let symbolic = !mode.is_empty()
        && !mode.starts_with("--")
        && mode.split(',').all(|clause| {
            let rest = clause.trim_start_matches(['u', 'g', 'o', 'a']);
            rest.starts_with(['+', '-', '=']) && rest.chars().all(|c| "+-=rwxXstugo".contains(c))
        });
    if octal || symbolic {
        Ok(())
    } else {
        Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid 'mode' {mode:?}: expected an octal mode such as 755 or a symbolic mode \
                 such as u+x"
            ),
        })
    }
}

/// Builds file operation commands for remote execution.
pub struct FileOpsCommandBuilder;

impl FileOpsCommandBuilder {
    /// Build a command to read a file with optional line range.
    ///
    /// Constructs: `sed -n -e '{start},{end}p' -- {path}` or `cat -- {path}`
    #[must_use]
    pub fn build_read_command(path: &str, offset: Option<u64>, limit: Option<u64>) -> String {
        let escaped = shell_escape(path);
        match (offset, limit) {
            (Some(off), Some(lim)) => {
                let end = off.saturating_add(lim);
                format!("sed -n -e '{off},{end}p' -- {escaped}")
            }
            (Some(off), None) => format!("sed -n -e '{off},$p' -- {escaped}"),
            (None, Some(lim)) => format!("head -n {lim} -- {escaped}"),
            (None, None) => format!("cat -- {escaped}"),
        }
    }

    /// Build a command to write content to a file.
    ///
    /// Constructs: `printf '%s' {content} > {path}` or append variant
    #[must_use]
    pub fn build_write_command(path: &str, content: &str, append: bool) -> String {
        let escaped = shell_escape(path);
        let operator = if append { ">>" } else { ">" };
        // The content is printf's ARGUMENT, never its format: as a format a
        // leading '-' is an option and `%`/`\` are interpreted.
        let content_escaped = shell_escape(content);
        format!("printf '%s' {content_escaped} {operator} {escaped}")
    }

    /// Build a chmod command.
    ///
    /// Constructs: `chmod [-R] {mode} {path}`
    ///
    /// The mode is validated (octal or symbolic) and then written without
    /// quotes: it is made of `[0-7+=,-rwxXstugoa]` only, and quoting it would
    /// hide `chmod 777` from the default command blacklist.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] when `mode` is neither an octal
    /// nor a symbolic mode.
    pub fn build_chmod_command(path: &str, mode: &str, recursive: bool) -> Result<String> {
        validate_chmod_mode(mode)?;
        let escaped = path_operand(path);
        let recursive_flag = if recursive { "-R " } else { "" };
        Ok(format!("chmod {recursive_flag}{mode} {escaped}"))
    }

    /// Build a chown command.
    ///
    /// Constructs: `chown [-R] {owner}[:{group}] {path}`
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] when `owner` or `group` starts
    /// with `-`.
    pub fn build_chown_command(
        path: &str,
        owner: &str,
        group: Option<&str>,
        recursive: bool,
    ) -> Result<String> {
        refuse_option_like("owner", owner)?;
        if let Some(g) = group {
            refuse_option_like("group", g)?;
        }
        let escaped = path_operand(path);
        let recursive_flag = if recursive { "-R " } else { "" };
        let ownership = if let Some(g) = group {
            let mut s = String::new();
            let _ = write!(s, "{owner}:{g}");
            s
        } else {
            owner.to_string()
        };
        let ownership_escaped = shell_escape(&ownership);
        Ok(format!(
            "chown {recursive_flag}{ownership_escaped} {escaped}"
        ))
    }

    /// Build a stat command.
    ///
    /// Constructs: `stat -c '{format}' {path}` (Linux)
    #[must_use]
    pub fn build_stat_command(path: &str) -> String {
        let escaped = shell_escape(path);
        format!("stat -c '%A %U %G %s %Y %n' -- {escaped} && file -b -- {escaped}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_command_simple() {
        let cmd = FileOpsCommandBuilder::build_read_command("/etc/hosts", None, None);
        assert!(cmd.contains("cat"));
        assert!(cmd.contains("/etc/hosts"));
    }

    #[test]
    fn test_read_command_with_offset_limit() {
        let cmd = FileOpsCommandBuilder::build_read_command("/var/log/syslog", Some(10), Some(20));
        assert!(cmd.contains("sed"));
        assert!(cmd.contains("10,30p"));
    }

    #[test]
    fn test_read_command_head_only() {
        let cmd = FileOpsCommandBuilder::build_read_command("/etc/hosts", None, Some(50));
        assert!(cmd.contains("head"));
        assert!(cmd.contains("-n 50"));
    }

    #[test]
    fn test_write_command_overwrite() {
        let cmd = FileOpsCommandBuilder::build_write_command("/tmp/test.txt", "hello", false);
        assert!(cmd.contains("> "));
        assert!(!cmd.contains(">>"));
    }

    #[test]
    fn test_write_command_append() {
        let cmd = FileOpsCommandBuilder::build_write_command("/tmp/test.txt", "hello", true);
        assert!(cmd.contains(">>"));
    }

    #[test]
    fn test_chmod_command() {
        let cmd =
            FileOpsCommandBuilder::build_chmod_command("/tmp/script.sh", "755", false).unwrap();
        assert!(cmd.contains("chmod"));
        assert!(cmd.contains("755"));
    }

    #[test]
    fn test_chmod_recursive() {
        let cmd = FileOpsCommandBuilder::build_chmod_command("/var/www", "755", true).unwrap();
        assert!(cmd.contains("-R"));
    }

    #[test]
    fn test_chown_command() {
        let cmd = FileOpsCommandBuilder::build_chown_command(
            "/tmp/file",
            "root",
            Some("www-data"),
            false,
        )
        .unwrap();
        assert!(cmd.contains("chown"));
        assert!(cmd.contains("root:www-data"));
    }

    #[test]
    fn test_chown_no_group() {
        let cmd =
            FileOpsCommandBuilder::build_chown_command("/tmp/file", "admin", None, false).unwrap();
        assert!(cmd.contains("admin"));
        assert!(!cmd.contains(':'));
    }

    #[test]
    fn test_stat_command() {
        let cmd = FileOpsCommandBuilder::build_stat_command("/etc/passwd");
        assert!(cmd.contains("stat"));
        assert!(cmd.contains("/etc/passwd"));
    }

    #[test]
    fn read_puts_the_path_after_end_of_options() {
        let plain = FileOpsCommandBuilder::build_read_command("-x", None, None);
        assert_eq!(plain, "cat -- '-x'");
        let head = FileOpsCommandBuilder::build_read_command("-x", None, Some(5));
        assert_eq!(head, "head -n 5 -- '-x'");
    }

    #[test]
    fn read_script_is_an_expression_and_the_path_cannot_replace_it() {
        let cmd = FileOpsCommandBuilder::build_read_command("--expression=1e id", Some(1), Some(5));
        assert_eq!(cmd, "sed -n -e '1,6p' -- '--expression=1e id'");
        let tail = FileOpsCommandBuilder::build_read_command("-i", Some(3), None);
        assert_eq!(tail, "sed -n -e '3,$p' -- '-i'");
    }

    #[test]
    fn write_content_is_printf_data_not_its_format() {
        let cmd = FileOpsCommandBuilder::build_write_command("/tmp/f", "- item %s \\n", false);
        assert_eq!(cmd, "printf '%s' '- item %s \\n' > '/tmp/f'");
        let append = FileOpsCommandBuilder::build_write_command("/tmp/f", "-x", true);
        assert_eq!(append, "printf '%s' '-x' >> '/tmp/f'");
    }

    #[test]
    fn stat_puts_the_path_after_end_of_options() {
        let cmd = FileOpsCommandBuilder::build_stat_command("-x");
        assert!(cmd.contains("%n' -- '-x' && file -b -- '-x'"), "{cmd}");
    }

    #[test]
    fn chmod_mode_is_validated_and_left_visible_to_the_blacklist() {
        let cmd = FileOpsCommandBuilder::build_chmod_command("/srv/data", "777", false).unwrap();
        assert_eq!(cmd, "chmod 777 '/srv/data'");
        let symbolic = FileOpsCommandBuilder::build_chmod_command("/p", "-x", true).unwrap();
        assert_eq!(symbolic, "chmod -R -x '/p'");
        for bad in ["", "7;id", "$(id)", "-ZQXdash", "u+x g", "75555", "--", "x"] {
            let err = FileOpsCommandBuilder::build_chmod_command("/p", bad, false).unwrap_err();
            assert!(err.to_string().contains("'mode'"), "{bad}: {err}");
        }
    }

    #[test]
    fn chmod_and_chown_make_a_dashed_path_relative() {
        let chmod = FileOpsCommandBuilder::build_chmod_command("-R", "755", false).unwrap();
        assert_eq!(chmod, "chmod 755 './-R'");
        let chown = FileOpsCommandBuilder::build_chown_command("-x", "root", None, false).unwrap();
        assert_eq!(chown, "chown 'root' './-x'");
    }

    #[test]
    fn chown_refuses_an_option_like_owner_or_group() {
        let owner = FileOpsCommandBuilder::build_chown_command("/p", "-R", None, false);
        assert!(owner.unwrap_err().to_string().contains("'owner'"));
        let group = FileOpsCommandBuilder::build_chown_command("/p", "root", Some("-h"), false);
        assert!(group.unwrap_err().to_string().contains("'group'"));
    }
}
