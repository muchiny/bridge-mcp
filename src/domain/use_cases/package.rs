//! Package Command Builder
//!
//! Builds package management CLI commands for remote execution via SSH.
//! Auto-detects the package manager: apt, yum, dnf, or apk.

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Validate a package name contains only safe characters.
///
/// Valid characters: alphanumeric, hyphen, underscore, dot, plus, colon, tilde, equals.
/// Examples: `nginx`, `libssl-dev`, `g++`, `nginx:amd64`, `nginx=1.24.0-1~focal`.
pub fn validate_package_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Package name cannot be empty".to_string(),
        });
    }
    if name.starts_with('-') {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid package name '{name}': a leading hyphen makes it an option to the \
                 package manager rather than a package."
            ),
        });
    }
    if name
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '+' | ':' | '~' | '='))
    {
        Ok(())
    } else {
        Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid package name '{name}'. Only alphanumeric, hyphen, underscore, dot, \
                 plus, colon, tilde, and equals allowed.",
            ),
        })
    }
}

/// Validate a search query contains only safe characters.
///
/// Same as package names but also allows `*` for wildcard patterns.
pub fn validate_search_query(query: &str) -> Result<()> {
    if query.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Search query cannot be empty".to_string(),
        });
    }
    if query.starts_with('-') {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid search query '{query}': a leading hyphen makes it an option to the \
                 tool that receives it rather than a pattern."
            ),
        });
    }
    if query
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '+' | ':' | '~' | '=' | '*'))
    {
        Ok(())
    } else {
        Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid search query '{query}'. Only alphanumeric, hyphen, underscore, dot, \
                 plus, colon, tilde, equals, and wildcard allowed.",
            ),
        })
    }
}

/// Validate a binary path contains only safe characters.
fn is_valid_binary_path(bin: &str) -> bool {
    !bin.is_empty()
        && bin
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'))
}

/// Generate a package manager detection prefix.
///
/// If `pkg_manager` is provided and valid, use it directly. If invalid,
/// falls back to auto-detection. Otherwise, auto-detect by probing for
/// `apt`, `dnf`, `yum`, or `apk`.
#[must_use]
pub fn pkg_detect_prefix(pkg_manager: Option<&str>) -> String {
    if let Some(pm) = pkg_manager {
        if is_valid_binary_path(pm) {
            return pm.to_string();
        }
        // Invalid binary path, fall back to auto-detection
        return pkg_detect_prefix(None);
    }
    "$(if command -v apt >/dev/null 2>&1; then echo apt; \
     elif command -v dnf >/dev/null 2>&1; then echo dnf; \
     elif command -v yum >/dev/null 2>&1; then echo yum; \
     elif command -v apk >/dev/null 2>&1; then echo apk; \
     else echo 'No supported package manager found on host' >&2; echo false; fi)"
        .to_string()
}

/// Builds package management commands for remote execution.
pub struct PackageCommandBuilder;

impl PackageCommandBuilder {
    /// Build a command to list installed packages.
    ///
    /// Constructs manager-appropriate list command.
    ///
    /// `filter` is passed to `grep` as `-e {pattern}`, never bare. Bare, it
    /// landed in grep's OPTION position, and shell-escaping does not help
    /// there: `grep -i '-rf/etc/hostname'` is one shell word, and getopt
    /// unbundles it into `-r` plus `-f/etc/hostname` — a recursive read of the
    /// SSH user's home directory, echoed into the tool's output. Measured
    /// against GNU grep 3.12. `ssh_pkg_list` is annotated `read_only`, so
    /// nothing asks the operator first.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `filter` is not a valid
    /// search pattern.
    pub fn build_list_command(pkg_manager: Option<&str>, filter: Option<&str>) -> Result<String> {
        let pm = pkg_detect_prefix(pkg_manager);
        let Some(f) = filter else {
            return Ok(format!(
                "{pm} list --installed 2>/dev/null || dpkg -l 2>/dev/null || rpm -qa 2>/dev/null"
            ));
        };
        validate_search_query(f)?;
        Ok(format!(
            "({pm} list --installed 2>/dev/null || dpkg -l 2>/dev/null || rpm -qa 2>/dev/null) | grep -i -e {}",
            shell_escape(f)
        ))
    }

    /// Build a command to search for packages.
    ///
    /// Constructs: `{pm} search {query}`
    #[must_use]
    pub fn build_search_command(pkg_manager: Option<&str>, query: &str) -> String {
        let pm = pkg_detect_prefix(pkg_manager);
        format!("{pm} search -- {}", shell_escape(query))
    }

    /// Build a command to install a package.
    ///
    /// Constructs: `{pm} install -y {package}`
    #[must_use]
    pub fn build_install_command(pkg_manager: Option<&str>, package: &str) -> String {
        let pm = pkg_detect_prefix(pkg_manager);
        format!("{pm} install -y -- {}", shell_escape(package))
    }

    /// Build a command to remove/uninstall a package.
    ///
    /// Constructs: `{pm} remove -y {package}` (apt/dnf/yum) or `{pm} del {package}` (apk)
    #[must_use]
    pub fn build_remove_command(pkg_manager: Option<&str>, package: &str) -> String {
        let pm = pkg_detect_prefix(pkg_manager);
        format!("{pm} remove -y -- {}", shell_escape(package))
    }

    /// Build a command to update packages.
    ///
    /// Constructs: `{pm} update && {pm} upgrade -y` (apt) or `{pm} update -y` (others)
    #[must_use]
    pub fn build_update_command(pkg_manager: Option<&str>, package: Option<&str>) -> String {
        let pm = pkg_detect_prefix(pkg_manager);
        if let Some(pkg) = package {
            format!("{pm} install -y -- {}", shell_escape(pkg))
        } else {
            "if command -v apt >/dev/null 2>&1; then apt update && apt upgrade -y; \
                 elif command -v dnf >/dev/null 2>&1; then dnf update -y; \
                 elif command -v yum >/dev/null 2>&1; then yum update -y; \
                 elif command -v apk >/dev/null 2>&1; then apk update && apk upgrade; \
                 else echo 'ERROR: No package manager found'; exit 127; fi"
                .to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkg_detect_prefix_explicit() {
        assert_eq!(pkg_detect_prefix(Some("apt")), "apt");
        assert_eq!(pkg_detect_prefix(Some("dnf")), "dnf");
    }

    #[test]
    fn test_pkg_detect_prefix_auto() {
        let prefix = pkg_detect_prefix(None);
        assert!(prefix.contains("command -v apt"));
        assert!(prefix.contains("dnf"));
        assert!(prefix.contains("yum"));
        assert!(prefix.contains("apk"));
    }

    #[test]
    fn test_list_command() {
        let cmd = PackageCommandBuilder::build_list_command(Some("apt"), None).unwrap();
        assert!(cmd.starts_with("apt list"));
    }

    #[test]
    fn test_list_command_with_filter() {
        let cmd = PackageCommandBuilder::build_list_command(Some("apt"), Some("nginx")).unwrap();
        assert!(cmd.contains("grep -i -e 'nginx'"));
    }

    #[test]
    fn test_list_filter_wraps_in_parentheses() {
        let cmd = PackageCommandBuilder::build_list_command(None, Some("curl")).unwrap();
        // Parentheses ensure grep applies to the entire fallback chain, not just rpm
        assert!(cmd.starts_with('('));
        assert!(cmd.contains(") | grep -i -e 'curl'"));
    }

    #[test]
    fn test_list_no_parentheses_without_filter() {
        let cmd = PackageCommandBuilder::build_list_command(None, None).unwrap();
        assert!(!cmd.starts_with('('));
    }

    #[test]
    fn test_search_command() {
        let cmd = PackageCommandBuilder::build_search_command(Some("apt"), "nginx");
        assert_eq!(cmd, "apt search -- 'nginx'");
    }

    #[test]
    fn test_install_command() {
        let cmd = PackageCommandBuilder::build_install_command(Some("apt"), "nginx");
        assert_eq!(cmd, "apt install -y -- 'nginx'");
    }

    #[test]
    fn test_update_command_all() {
        let cmd = PackageCommandBuilder::build_update_command(None, None);
        assert!(cmd.contains("apt update"));
        assert!(cmd.contains("dnf update -y"));
    }

    #[test]
    fn test_update_command_specific() {
        let cmd = PackageCommandBuilder::build_update_command(Some("apt"), Some("nginx"));
        assert_eq!(cmd, "apt install -y -- 'nginx'");
    }

    // ============== Remove Command ==============

    #[test]
    fn test_remove_command() {
        let cmd = PackageCommandBuilder::build_remove_command(Some("apt"), "nginx");
        assert_eq!(cmd, "apt remove -y -- 'nginx'");
    }

    #[test]
    fn test_remove_command_dnf() {
        let cmd = PackageCommandBuilder::build_remove_command(Some("dnf"), "httpd");
        assert_eq!(cmd, "dnf remove -y -- 'httpd'");
    }

    #[test]
    fn test_remove_command_auto_detect() {
        let cmd = PackageCommandBuilder::build_remove_command(None, "nginx");
        assert!(cmd.contains("command -v apt"));
        assert!(cmd.contains("remove -y -- 'nginx'"));
    }

    #[test]
    fn test_remove_injection_in_package() {
        let cmd = PackageCommandBuilder::build_remove_command(Some("apt"), "nginx; rm -rf /");
        assert_eq!(cmd, "apt remove -y -- 'nginx; rm -rf /'");
    }

    // ============== Shell Injection Prevention ==============

    #[test]
    fn test_install_injection_in_package() {
        let cmd = PackageCommandBuilder::build_install_command(Some("apt"), "nginx; rm -rf /");
        assert_eq!(cmd, "apt install -y -- 'nginx; rm -rf /'");
    }

    #[test]
    fn test_search_injection_in_query() {
        let cmd = PackageCommandBuilder::build_search_command(Some("apt"), "nginx$(whoami)");
        assert_eq!(cmd, "apt search -- 'nginx$(whoami)'");
    }

    /// The filter used to be escaped and passed through. Escaping made it
    /// one shell word, which was never the question — the question was what
    /// `grep` does with that word. It is refused outright now.
    #[test]
    fn test_list_injection_in_filter() {
        PackageCommandBuilder::build_list_command(Some("apt"), Some("nginx | cat /etc/passwd"))
            .expect_err("a filter carrying shell text must be refused");
    }

    /// The measured attack: `-rf<file>` unbundles into `-r` plus
    /// `-f<file>`, so a package-list call became a recursive read of the SSH
    /// user's home. Two independent gates now stop it — the leading hyphen is
    /// refused, and `-e` would put it in pattern position anyway.
    #[test]
    fn a_filter_cannot_become_a_grep_option() {
        for hostile in ["-rf/etc/hostname", "-r", "--include=*.pem", "-e"] {
            PackageCommandBuilder::build_list_command(Some("apt"), Some(hostile))
                .expect_err("a filter that grep would read as an option must be refused");
        }

        // Second gate, independent of the first: an ACCEPTED filter still
        // reaches grep in pattern position. Losing either one alone must
        // fail this test.
        let cmd = PackageCommandBuilder::build_list_command(Some("apt"), Some("nginx")).unwrap();
        assert!(
            cmd.contains("grep -i -e 'nginx'"),
            "the filter must be an argument of -e, never a bare word: {cmd}"
        );
    }

    #[test]
    fn test_install_package_with_single_quotes() {
        let cmd = PackageCommandBuilder::build_install_command(Some("apt"), "python3's-tools");
        assert!(cmd.contains("'python3'\\''s-tools'"));
    }

    // ============== Package Manager Variants ==============

    #[test]
    fn test_search_command_dnf() {
        let cmd = PackageCommandBuilder::build_search_command(Some("dnf"), "httpd");
        assert_eq!(cmd, "dnf search -- 'httpd'");
    }

    #[test]
    fn test_search_command_yum() {
        let cmd = PackageCommandBuilder::build_search_command(Some("yum"), "httpd");
        assert_eq!(cmd, "yum search -- 'httpd'");
    }

    #[test]
    fn test_search_command_apk() {
        let cmd = PackageCommandBuilder::build_search_command(Some("apk"), "nginx");
        assert_eq!(cmd, "apk search -- 'nginx'");
    }

    #[test]
    fn test_install_command_dnf() {
        let cmd = PackageCommandBuilder::build_install_command(Some("dnf"), "httpd");
        assert_eq!(cmd, "dnf install -y -- 'httpd'");
    }

    #[test]
    fn test_install_command_yum() {
        let cmd = PackageCommandBuilder::build_install_command(Some("yum"), "httpd");
        assert_eq!(cmd, "yum install -y -- 'httpd'");
    }

    #[test]
    fn test_install_command_apk() {
        let cmd = PackageCommandBuilder::build_install_command(Some("apk"), "nginx");
        assert_eq!(cmd, "apk install -y -- 'nginx'");
    }

    // ============== Auto-Detect Tests ==============

    #[test]
    fn test_list_command_auto_detect() {
        let cmd = PackageCommandBuilder::build_list_command(None, None).unwrap();
        assert!(cmd.contains("command -v apt"));
    }

    #[test]
    fn test_search_command_auto_detect() {
        let cmd = PackageCommandBuilder::build_search_command(None, "nginx");
        assert!(cmd.contains("command -v apt"));
        assert!(cmd.contains("search -- 'nginx'"));
    }

    #[test]
    fn test_install_command_auto_detect() {
        let cmd = PackageCommandBuilder::build_install_command(None, "nginx");
        assert!(cmd.contains("command -v apt"));
        assert!(cmd.contains("install -y -- 'nginx'"));
    }

    // ============== Edge Cases ==============

    #[test]
    fn test_install_package_with_version() {
        let cmd = PackageCommandBuilder::build_install_command(Some("apt"), "nginx=1.24.0-1~focal");
        assert!(cmd.contains("'nginx=1.24.0-1~focal'"));
    }

    #[test]
    fn test_list_no_filter_no_grep() {
        let cmd = PackageCommandBuilder::build_list_command(Some("apt"), None).unwrap();
        assert!(!cmd.contains("grep"));
    }

    #[test]
    fn test_update_command_yum_all() {
        let cmd = PackageCommandBuilder::build_update_command(None, None);
        assert!(cmd.contains("yum update -y"));
    }

    #[test]
    fn test_update_command_apk_all() {
        let cmd = PackageCommandBuilder::build_update_command(None, None);
        assert!(cmd.contains("apk update && apk upgrade"));
    }

    #[test]
    fn test_update_specific_dnf() {
        let cmd = PackageCommandBuilder::build_update_command(Some("dnf"), Some("httpd"));
        assert_eq!(cmd, "dnf install -y -- 'httpd'");
    }

    #[test]
    fn test_pkg_detect_prefix_yum() {
        assert_eq!(pkg_detect_prefix(Some("yum")), "yum");
    }

    #[test]
    fn test_pkg_detect_prefix_apk() {
        assert_eq!(pkg_detect_prefix(Some("apk")), "apk");
    }

    // ============== Binary Path Validation ==============

    #[test]
    fn test_pkg_detect_prefix_injection_falls_back() {
        let prefix = pkg_detect_prefix(Some("apt; rm -rf /"));
        assert!(prefix.contains("command -v apt"));
    }

    #[test]
    fn test_pkg_detect_prefix_valid_path() {
        assert_eq!(pkg_detect_prefix(Some("/usr/bin/apt")), "/usr/bin/apt");
    }

    #[test]
    fn test_pkg_detect_prefix_shell_metachar_falls_back() {
        let prefix = pkg_detect_prefix(Some("apt && whoami"));
        assert!(prefix.contains("command -v apt"));
    }

    // ============== Update Specific Package (yum/apk) ==============

    #[test]
    fn test_update_yum_specific_package() {
        let cmd = PackageCommandBuilder::build_update_command(Some("yum"), Some("httpd"));
        assert_eq!(cmd, "yum install -y -- 'httpd'");
    }

    #[test]
    fn test_update_apk_specific_package() {
        let cmd = PackageCommandBuilder::build_update_command(Some("apk"), Some("nginx"));
        assert_eq!(cmd, "apk install -y -- 'nginx'");
    }

    #[test]
    fn test_install_empty_package_name() {
        let cmd = PackageCommandBuilder::build_install_command(Some("apt"), "");
        assert_eq!(cmd, "apt install -y -- ''");
    }

    // ============== Package Name Validation ==============

    #[test]
    fn test_validate_package_name_valid() {
        assert!(validate_package_name("nginx").is_ok());
        assert!(validate_package_name("libssl-dev").is_ok());
        assert!(validate_package_name("python3.11").is_ok());
        assert!(validate_package_name("g++").is_ok());
        assert!(validate_package_name("nginx:amd64").is_ok());
        assert!(validate_package_name("nginx=1.24.0-1~focal").is_ok());
        assert!(validate_package_name("python3_distutils").is_ok());
    }

    #[test]
    fn test_validate_package_name_empty() {
        assert!(validate_package_name("").is_err());
    }

    #[test]
    fn test_validate_package_name_injection_semicolon() {
        assert!(validate_package_name("curl; rm -r /").is_err());
    }

    #[test]
    fn test_validate_package_name_injection_pipe() {
        assert!(validate_package_name("curl | cat /etc/passwd").is_err());
    }

    #[test]
    fn test_validate_package_name_injection_subshell() {
        assert!(validate_package_name("curl$(whoami)").is_err());
    }

    #[test]
    fn test_validate_package_name_injection_backtick() {
        assert!(validate_package_name("curl`whoami`").is_err());
    }

    #[test]
    fn test_validate_package_name_space() {
        assert!(validate_package_name("curl rm").is_err());
    }

    // ============== Search Query Validation ==============

    #[test]
    fn test_validate_search_query_valid() {
        assert!(validate_search_query("nginx").is_ok());
        assert!(validate_search_query("lib*").is_ok());
        assert!(validate_search_query("python3.11").is_ok());
    }

    #[test]
    fn test_validate_search_query_empty() {
        assert!(validate_search_query("").is_err());
    }

    #[test]
    fn test_validate_search_query_injection() {
        assert!(validate_search_query("nginx$(whoami)").is_err());
        assert!(validate_search_query("nginx; rm -r /").is_err());
    }
}
