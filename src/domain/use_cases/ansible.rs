//! Ansible Command Builder
//!
//! Builds `ansible-playbook`, `ansible-inventory`, and `ansible` (ad-hoc)
//! CLI commands for remote execution via SSH.

use std::collections::HashMap;
use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Write verbose flags (`-v`, `-vv`, `-vvv`, `-vvvv`) capped at 4.
fn write_verbose_flags(cmd: &mut String, level: u8) {
    let capped = level.min(4);
    if capped > 0 {
        cmd.push_str(" -");
        for _ in 0..capped {
            cmd.push('v');
        }
    }
}

/// Allowed Ansible stdout callback plugins (whitelist for injection prevention).
const ALLOWED_CALLBACKS: &[&str] = &[
    "json", "yaml", "dense", "minimal", "tree", "default", "oneline", "debug", "null",
];

/// Builds Ansible CLI commands for remote execution.
pub struct AnsibleCommandBuilder;

impl AnsibleCommandBuilder {
    /// Build an `ansible-playbook` command.
    ///
    /// Constructs a shell command string like:
    /// `[ANSIBLE_STDOUT_CALLBACK={callback} ][cd {working_dir} && ]
    /// ansible-playbook {playbook} [-i {inventory}]
    /// [--limit {limit}] [--tags {tags}] [--skip-tags {skip}]
    /// [-e key=value ...] [--check] [--diff] [-v..vvvv] [-f {forks}]
    /// [-b] [--become-user {user}]`
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn build_playbook_command(
        playbook: &str,
        inventory: Option<&str>,
        limit: Option<&str>,
        tags: Option<&str>,
        skip_tags: Option<&str>,
        extra_vars: Option<&HashMap<String, String>>,
        check: bool,
        diff: bool,
        verbose: Option<u8>,
        forks: Option<u32>,
        use_become: bool,
        become_user: Option<&str>,
        working_dir: Option<&str>,
        callback: Option<&str>,
        vault_password_file: Option<&str>,
        vault_id: Option<&str>,
    ) -> String {
        let mut cmd = String::new();

        if let Some(cb) = callback {
            let _ = write!(cmd, "ANSIBLE_STDOUT_CALLBACK={} ", shell_escape(cb));
        }

        if let Some(dir) = working_dir {
            let _ = write!(cmd, "cd {} && ", shell_escape(dir));
        }

        let _ = write!(cmd, "ansible-playbook {}", shell_escape(playbook));

        if let Some(inv) = inventory {
            let _ = write!(cmd, " -i {}", shell_escape(inv));
        }

        if let Some(lim) = limit {
            let _ = write!(cmd, " --limit {}", shell_escape(lim));
        }

        if let Some(t) = tags {
            let _ = write!(cmd, " --tags {}", shell_escape(t));
        }

        if let Some(st) = skip_tags {
            let _ = write!(cmd, " --skip-tags {}", shell_escape(st));
        }

        if let Some(vars) = extra_vars {
            let mut keys: Vec<&String> = vars.keys().collect();
            keys.sort();
            for key in keys {
                let value = &vars[key];
                let _ = write!(cmd, " -e {}={}", shell_escape(key), shell_escape(value));
            }
        }

        if check {
            cmd.push_str(" --check");
        }

        if diff {
            cmd.push_str(" --diff");
        }

        if let Some(v) = verbose {
            write_verbose_flags(&mut cmd, v);
        }

        if let Some(f) = forks {
            let _ = write!(cmd, " -f {f}");
        }

        if use_become {
            cmd.push_str(" -b");
        }

        if let Some(user) = become_user {
            let _ = write!(cmd, " --become-user {}", shell_escape(user));
        }

        if let Some(vpf) = vault_password_file {
            let _ = write!(cmd, " --vault-password-file {}", shell_escape(vpf));
        }

        if let Some(vid) = vault_id {
            let _ = write!(cmd, " --vault-id {}", shell_escape(vid));
        }

        cmd
    }

    /// Build an `ansible-inventory` command.
    ///
    /// Constructs a shell command string like:
    /// `ansible-inventory [-i {inventory}] [--list] [--graph [{group}]]
    /// [--host {host}] [--yaml] [--vars]`
    ///
    /// If none of `list`, `graph`, or `host_pattern` is set, defaults to `--list`.
    #[must_use]
    #[expect(clippy::fn_params_excessive_bools)]
    pub fn build_inventory_command(
        inventory: Option<&str>,
        list: bool,
        graph: bool,
        host_pattern: Option<&str>,
        group: Option<&str>,
        yaml: bool,
        vars: bool,
    ) -> String {
        let mut cmd = String::from("ansible-inventory");

        if let Some(inv) = inventory {
            let _ = write!(cmd, " -i {}", shell_escape(inv));
        }

        let has_action = list || graph || host_pattern.is_some();

        if list {
            cmd.push_str(" --list");
        }

        if graph {
            if let Some(g) = group {
                let _ = write!(cmd, " --graph {}", shell_escape(g));
            } else {
                cmd.push_str(" --graph");
            }
        }

        if let Some(host) = host_pattern {
            let _ = write!(cmd, " --host {}", shell_escape(host));
        }

        if !has_action {
            cmd.push_str(" --list");
        }

        if yaml {
            cmd.push_str(" --yaml");
        }

        if vars {
            cmd.push_str(" --vars");
        }

        cmd
    }

    /// Build an `ansible` ad-hoc command.
    ///
    /// Constructs a shell command string like:
    /// `ansible {pattern} -m {module} [-a {args}] [-i {inventory}]
    /// [-b] [--become-user {user}] [-u {user}] [-f {forks}]
    /// [-v..vvvv] [-C]`
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn build_adhoc_command(
        pattern: &str,
        module: &str,
        args: Option<&str>,
        inventory: Option<&str>,
        use_become: bool,
        become_user: Option<&str>,
        user: Option<&str>,
        forks: Option<u32>,
        verbose: Option<u8>,
        check: bool,
        vault_password_file: Option<&str>,
        vault_id: Option<&str>,
    ) -> String {
        let mut cmd = String::new();

        let _ = write!(
            cmd,
            "ansible {} -m {}",
            shell_escape(pattern),
            shell_escape(module)
        );

        if let Some(a) = args {
            let _ = write!(cmd, " -a {}", shell_escape(a));
        }

        if let Some(inv) = inventory {
            let _ = write!(cmd, " -i {}", shell_escape(inv));
        }

        if use_become {
            cmd.push_str(" -b");
        }

        if let Some(bu) = become_user {
            let _ = write!(cmd, " --become-user {}", shell_escape(bu));
        }

        if let Some(u) = user {
            let _ = write!(cmd, " -u {}", shell_escape(u));
        }

        if let Some(f) = forks {
            let _ = write!(cmd, " -f {f}");
        }

        if let Some(v) = verbose {
            write_verbose_flags(&mut cmd, v);
        }

        if check {
            cmd.push_str(" -C");
        }

        if let Some(vpf) = vault_password_file {
            let _ = write!(cmd, " --vault-password-file {}", shell_escape(vpf));
        }

        if let Some(vid) = vault_id {
            let _ = write!(cmd, " --vault-id {}", shell_escape(vid));
        }

        cmd
    }

    /// Build an `ansible -m setup` command to gather facts.
    ///
    /// Constructs: `ansible {pattern} -m setup [-a "filter={filter}"]
    /// [-i {inventory}] [-b] [--become-user {user}]`
    #[must_use]
    pub fn build_facts_command(
        pattern: &str,
        filter: Option<&str>,
        inventory: Option<&str>,
        use_become: bool,
        become_user: Option<&str>,
    ) -> String {
        let mut cmd = String::new();

        let _ = write!(cmd, "ansible {} -m setup", shell_escape(pattern));

        if let Some(f) = filter {
            let _ = write!(cmd, " -a 'filter={}'", shell_escape(f));
        }

        if let Some(inv) = inventory {
            let _ = write!(cmd, " -i {}", shell_escape(inv));
        }

        if use_become {
            cmd.push_str(" -b");
        }

        if let Some(user) = become_user {
            let _ = write!(cmd, " --become-user {}", shell_escape(user));
        }

        cmd
    }

    /// Build an `ansible-lint` command.
    ///
    /// Constructs: `ansible-lint {target} [--format {format}] [-p]`
    #[must_use]
    pub fn build_lint_command(target: &str, format: Option<&str>, parseable: bool) -> String {
        let mut cmd = String::new();

        let _ = write!(cmd, "ansible-lint {}", shell_escape(target));

        if let Some(fmt) = format {
            let _ = write!(cmd, " --format {}", shell_escape(fmt));
        }

        if parseable {
            cmd.push_str(" -p");
        }

        cmd
    }

    /// Build an `ansible-config dump` command.
    ///
    /// Constructs: `ansible-config dump [--only-changed] [--format {format}]`
    #[must_use]
    pub fn build_config_command(only_changed: bool, format: Option<&str>) -> String {
        let mut cmd = String::from("ansible-config dump");

        if only_changed {
            cmd.push_str(" --only-changed");
        }

        if let Some(fmt) = format {
            let _ = write!(cmd, " --format {}", shell_escape(fmt));
        }

        cmd
    }

    /// Validate a playbook path.
    ///
    /// Rejects paths with `..` (directory traversal).
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` if the path contains `..`.
    pub fn validate_playbook_path(playbook: &str) -> Result<()> {
        if playbook.contains("..") {
            return Err(BridgeError::CommandDenied {
                reason: "Path traversal not allowed in playbook path".to_string(),
            });
        }
        Ok(())
    }

    /// Validate an Ansible stdout callback name.
    ///
    /// Only allows known callback names to prevent command injection.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` if the callback is not in the
    /// allow list.
    pub fn validate_callback(callback: &str) -> Result<()> {
        if !ALLOWED_CALLBACKS.contains(&callback) {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "Unknown callback '{}'. Allowed: {}",
                    callback,
                    ALLOWED_CALLBACKS.join(", ")
                ),
            });
        }
        Ok(())
    }

    /// Validate a lint target path.
    ///
    /// Rejects paths with `..` (directory traversal).
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` if the path contains `..`.
    pub fn validate_lint_target(target: &str) -> Result<()> {
        if target.contains("..") {
            return Err(BridgeError::CommandDenied {
                reason: "Path traversal not allowed in lint target".to_string(),
            });
        }
        Ok(())
    }

    /// Validate an ansible module for safety.
    ///
    /// Blocks the `raw`, `shell`, and `command` modules when args contain
    /// dangerous patterns such as `rm -rf`, `mkfs`, `dd if=`,
    /// `> /dev/`, or `chmod 777`.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` if a dangerous combination is
    /// detected.
    pub fn validate_adhoc_module(module: &str, args: Option<&str>) -> Result<()> {
        let dangerous_modules = ["raw", "shell", "command"];
        let dangerous_patterns = ["rm -rf", "mkfs", "dd if=", "> /dev/", "chmod 777"];

        if dangerous_modules.contains(&module)
            && let Some(a) = args
        {
            let lower = a.to_lowercase();
            for pattern in &dangerous_patterns {
                if lower.contains(pattern) {
                    return Err(BridgeError::CommandDenied {
                        reason: format!(
                            "Dangerous pattern '{pattern}' not \
                             allowed with module '{module}'"
                        ),
                    });
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============== Playbook Command Tests ==============

    #[test]
    fn test_build_playbook_minimal() {
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "site.yml", None, None, None, None, None, false, false, None, None, false, None, None,
            None, None, None,
        );
        assert_eq!(cmd, "ansible-playbook 'site.yml'");
    }

    #[test]
    fn test_build_playbook_all_options() {
        let mut vars = HashMap::new();
        vars.insert("env".to_string(), "prod".to_string());
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "deploy.yml",
            Some("/etc/ansible/hosts"),
            Some("webservers"),
            Some("deploy,config"),
            Some("slow"),
            Some(&vars),
            true,
            true,
            Some(2),
            Some(10),
            true,
            Some("deploy_user"),
            Some("/opt/ansible"),
            None,
            None,
            None,
        );
        assert!(cmd.starts_with("cd '/opt/ansible' && "));
        assert!(cmd.contains("ansible-playbook 'deploy.yml'"));
        assert!(cmd.contains("-i '/etc/ansible/hosts'"));
        assert!(cmd.contains("--limit 'webservers'"));
        assert!(cmd.contains("--tags 'deploy,config'"));
        assert!(cmd.contains("--skip-tags 'slow'"));
        assert!(cmd.contains("-e 'env'='prod'"));
        assert!(cmd.contains("--check"));
        assert!(cmd.contains("--diff"));
        assert!(cmd.contains("-vv"));
        assert!(cmd.contains("-f 10"));
        assert!(cmd.contains(" -b"));
        assert!(cmd.contains("--become-user 'deploy_user'"));
    }

    #[test]
    fn test_build_playbook_with_extra_vars() {
        let mut vars = HashMap::new();
        vars.insert("version".to_string(), "1.2.3".to_string());
        vars.insert("env".to_string(), "staging".to_string());
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "deploy.yml",
            None,
            None,
            None,
            None,
            Some(&vars),
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
        );
        // Keys are sorted, so env comes before version
        assert!(cmd.contains("-e 'env'='staging'"));
        assert!(cmd.contains("-e 'version'='1.2.3'"));
    }

    #[test]
    fn test_build_playbook_with_working_dir() {
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "site.yml",
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            false,
            None,
            Some("/home/deploy/playbooks"),
            None,
            None,
            None,
        );
        assert!(cmd.starts_with("cd '/home/deploy/playbooks' && "));
        assert!(cmd.contains("ansible-playbook 'site.yml'"));
    }

    #[test]
    fn test_build_playbook_verbose_levels() {
        for level in 0u8..=4 {
            let cmd = AnsibleCommandBuilder::build_playbook_command(
                "site.yml",
                None,
                None,
                None,
                None,
                None,
                false,
                false,
                Some(level),
                None,
                false,
                None,
                None,
                None,
                None,
                None,
            );
            if level == 0 {
                assert!(!cmd.contains("-v"), "level 0 should not have -v");
            } else {
                let expected_v = format!("-{}", "v".repeat(level as usize));
                assert!(
                    cmd.contains(&expected_v),
                    "level {level} should contain {expected_v}, \
                     got: {cmd}"
                );
            }
        }
    }

    #[test]
    fn test_build_playbook_verbose_capped() {
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "site.yml",
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            Some(10),
            None,
            false,
            None,
            None,
            None,
            None,
            None,
        );
        // Should be capped at -vvvv (4)
        assert!(cmd.contains("-vvvv"));
        assert!(!cmd.contains("-vvvvv"));
    }

    #[test]
    fn test_build_playbook_shell_escape() {
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "my playbook's.yml",
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(cmd.contains("'my playbook'\\''s.yml'"));
    }

    // ============== Inventory Command Tests ==============

    #[test]
    fn test_build_inventory_list() {
        let cmd = AnsibleCommandBuilder::build_inventory_command(
            Some("/etc/ansible/hosts"),
            true,
            false,
            None,
            None,
            false,
            false,
        );
        assert!(cmd.contains("ansible-inventory"));
        assert!(cmd.contains("-i '/etc/ansible/hosts'"));
        assert!(cmd.contains("--list"));
    }

    #[test]
    fn test_build_inventory_graph() {
        let cmd = AnsibleCommandBuilder::build_inventory_command(
            None, false, true, None, None, false, false,
        );
        assert!(cmd.contains("--graph"));
        assert!(!cmd.contains("--list"));
    }

    #[test]
    fn test_build_inventory_graph_with_group() {
        let cmd = AnsibleCommandBuilder::build_inventory_command(
            None,
            false,
            true,
            None,
            Some("webservers"),
            false,
            false,
        );
        assert!(cmd.contains("--graph 'webservers'"));
    }

    #[test]
    fn test_build_inventory_host() {
        let cmd = AnsibleCommandBuilder::build_inventory_command(
            None,
            false,
            false,
            Some("server1"),
            None,
            false,
            false,
        );
        assert!(cmd.contains("--host 'server1'"));
        assert!(!cmd.contains("--list"));
    }

    #[test]
    fn test_build_inventory_default_list() {
        let cmd = AnsibleCommandBuilder::build_inventory_command(
            None, false, false, None, None, false, false,
        );
        assert!(cmd.contains("--list"));
    }

    #[test]
    fn test_build_inventory_yaml() {
        let cmd = AnsibleCommandBuilder::build_inventory_command(
            None, true, false, None, None, true, false,
        );
        assert!(cmd.contains("--list"));
        assert!(cmd.contains("--yaml"));
    }

    // ============== Adhoc Command Tests ==============

    #[test]
    fn test_build_adhoc_ping() {
        let cmd = AnsibleCommandBuilder::build_adhoc_command(
            "all", "ping", None, None, false, None, None, None, None, false, None, None,
        );
        assert_eq!(cmd, "ansible 'all' -m 'ping'");
    }

    #[test]
    fn test_build_adhoc_all_options() {
        let cmd = AnsibleCommandBuilder::build_adhoc_command(
            "webservers",
            "shell",
            Some("uptime"),
            Some("/etc/ansible/hosts"),
            true,
            Some("root"),
            Some("admin"),
            Some(5),
            Some(3),
            true,
            None,
            None,
        );
        assert!(cmd.contains("ansible 'webservers' -m 'shell'"));
        assert!(cmd.contains("-a 'uptime'"));
        assert!(cmd.contains("-i '/etc/ansible/hosts'"));
        assert!(cmd.contains(" -b"));
        assert!(cmd.contains("--become-user 'root'"));
        assert!(cmd.contains("-u 'admin'"));
        assert!(cmd.contains("-f 5"));
        assert!(cmd.contains("-vvv"));
        assert!(cmd.contains("-C"));
    }

    #[test]
    fn test_build_adhoc_shell_module() {
        let cmd = AnsibleCommandBuilder::build_adhoc_command(
            "all",
            "shell",
            Some("cat /etc/hostname"),
            None,
            false,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
        );
        assert!(cmd.contains("-m 'shell'"));
        assert!(cmd.contains("-a 'cat /etc/hostname'"));
    }

    // ============== Validation Tests ==============

    #[test]
    fn test_validate_playbook_path_ok() {
        assert!(AnsibleCommandBuilder::validate_playbook_path("site.yml").is_ok());
        assert!(AnsibleCommandBuilder::validate_playbook_path("playbooks/deploy.yml").is_ok());
        assert!(AnsibleCommandBuilder::validate_playbook_path("/opt/ansible/site.yml").is_ok());
    }

    #[test]
    fn test_validate_playbook_path_traversal() {
        let result = AnsibleCommandBuilder::validate_playbook_path("../../../etc/passwd");
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("Path traversal"));
            }
            e => {
                panic!("Expected CommandDenied error, got: {e:?}");
            }
        }

        assert!(AnsibleCommandBuilder::validate_playbook_path("roles/../site.yml").is_err());
    }

    #[test]
    fn test_validate_adhoc_safe_modules() {
        assert!(AnsibleCommandBuilder::validate_adhoc_module("ping", None).is_ok());
        assert!(AnsibleCommandBuilder::validate_adhoc_module("setup", None).is_ok());
        assert!(
            AnsibleCommandBuilder::validate_adhoc_module("copy", Some("src=/tmp/a dest=/tmp/b"))
                .is_ok()
        );
    }

    #[test]
    fn test_validate_adhoc_raw_with_rm() {
        let result = AnsibleCommandBuilder::validate_adhoc_module("raw", Some("rm -rf /"));
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("rm -rf"));
                assert!(reason.contains("raw"));
            }
            e => {
                panic!("Expected CommandDenied error, got: {e:?}");
            }
        }
    }

    #[test]
    fn test_validate_adhoc_shell_with_mkfs() {
        let result =
            AnsibleCommandBuilder::validate_adhoc_module("shell", Some("mkfs.ext4 /dev/sda1"));
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("mkfs"));
                assert!(reason.contains("shell"));
            }
            e => {
                panic!("Expected CommandDenied error, got: {e:?}");
            }
        }
    }

    #[test]
    fn test_validate_adhoc_shell_safe_args() {
        assert!(AnsibleCommandBuilder::validate_adhoc_module("shell", Some("ls -la /tmp")).is_ok());
        assert!(AnsibleCommandBuilder::validate_adhoc_module("command", Some("whoami")).is_ok());
        assert!(AnsibleCommandBuilder::validate_adhoc_module("raw", Some("uptime")).is_ok());
    }

    #[test]
    fn test_validate_adhoc_command_with_dd() {
        let result = AnsibleCommandBuilder::validate_adhoc_module(
            "command",
            Some("dd if=/dev/zero of=/dev/sda"),
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("dd if="));
                assert!(reason.contains("command"));
            }
            e => {
                panic!("Expected CommandDenied error, got: {e:?}");
            }
        }
    }

    // ============== Additional Edge Case Tests ==============

    #[test]
    fn test_validate_adhoc_redirect_to_dev() {
        let result =
            AnsibleCommandBuilder::validate_adhoc_module("shell", Some("echo x > /dev/sda"));
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("> /dev/"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_validate_adhoc_chmod_777() {
        let result =
            AnsibleCommandBuilder::validate_adhoc_module("raw", Some("chmod 777 /etc/passwd"));
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("chmod 777"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_validate_adhoc_dangerous_module_no_args() {
        // Dangerous module with no args should be OK (no pattern to match)
        assert!(AnsibleCommandBuilder::validate_adhoc_module("raw", None).is_ok());
        assert!(AnsibleCommandBuilder::validate_adhoc_module("shell", None).is_ok());
        assert!(AnsibleCommandBuilder::validate_adhoc_module("command", None).is_ok());
    }

    #[test]
    fn test_build_adhoc_verbose_capped() {
        let cmd = AnsibleCommandBuilder::build_adhoc_command(
            "all",
            "ping",
            None,
            None,
            false,
            None,
            None,
            None,
            Some(10), // Should be capped at 4
            false,
            None,
            None,
        );
        // Should have -vvvv (4 v's max), not -vvvvvvvvvv
        assert!(cmd.contains("-vvvv"));
        let count = cmd.matches("-vvvv").count();
        assert_eq!(count, 1); // Exactly one -vvvv, not more
    }

    // ============== Security: Injection Prevention Tests ==============

    #[test]
    fn test_extra_vars_key_injection_prevented() {
        let mut vars = HashMap::new();
        vars.insert("$(whoami)".to_string(), "bar".to_string());
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "site.yml",
            None,
            None,
            None,
            None,
            Some(&vars),
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
        );
        // Key should be escaped, not interpreted
        assert!(cmd.contains("-e '$(whoami)'='bar'"));
        assert!(!cmd.contains("-e $(whoami)="));
    }

    #[test]
    fn test_build_inventory_vars_without_list() {
        let cmd = AnsibleCommandBuilder::build_inventory_command(
            None,  // inventory
            false, // list
            false, // graph
            None,  // host
            None,  // group
            false, // yaml
            true,  // vars
        );
        assert!(cmd.contains("ansible-inventory"));
        assert!(cmd.contains("--vars"));
    }

    // ============== Callback Tests ==============

    #[test]
    fn test_build_playbook_with_callback() {
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "site.yml",
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            Some("json"),
            None,
            None,
        );
        assert!(cmd.starts_with("ANSIBLE_STDOUT_CALLBACK='json' "));
        assert!(cmd.contains("ansible-playbook 'site.yml'"));
    }

    #[test]
    fn test_build_playbook_callback_with_working_dir() {
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "site.yml",
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            false,
            None,
            Some("/opt/ansible"),
            Some("dense"),
            None,
            None,
        );
        assert!(cmd.starts_with("ANSIBLE_STDOUT_CALLBACK='dense' cd '/opt/ansible' && "));
    }

    #[test]
    fn test_validate_callback_allowed() {
        assert!(AnsibleCommandBuilder::validate_callback("json").is_ok());
        assert!(AnsibleCommandBuilder::validate_callback("yaml").is_ok());
        assert!(AnsibleCommandBuilder::validate_callback("dense").is_ok());
        assert!(AnsibleCommandBuilder::validate_callback("minimal").is_ok());
        assert!(AnsibleCommandBuilder::validate_callback("default").is_ok());
    }

    #[test]
    fn test_validate_callback_rejected() {
        let result = AnsibleCommandBuilder::validate_callback("$(whoami)");
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("Unknown callback"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    // ============== Facts Command Tests ==============

    #[test]
    fn test_build_facts_minimal() {
        let cmd = AnsibleCommandBuilder::build_facts_command("all", None, None, false, None);
        assert_eq!(cmd, "ansible 'all' -m setup");
    }

    #[test]
    fn test_build_facts_with_filter() {
        let cmd = AnsibleCommandBuilder::build_facts_command(
            "webservers",
            Some("ansible_distribution*"),
            Some("hosts.ini"),
            true,
            Some("root"),
        );
        assert!(cmd.contains("ansible 'webservers' -m setup"));
        assert!(cmd.contains("-a 'filter='ansible_distribution*''"));
        assert!(cmd.contains("-i 'hosts.ini'"));
        assert!(cmd.contains(" -b"));
        assert!(cmd.contains("--become-user 'root'"));
    }

    // ============== Lint Command Tests ==============

    #[test]
    fn test_build_lint_minimal() {
        let cmd = AnsibleCommandBuilder::build_lint_command("site.yml", None, false);
        assert_eq!(cmd, "ansible-lint 'site.yml'");
    }

    #[test]
    fn test_build_lint_with_format() {
        let cmd = AnsibleCommandBuilder::build_lint_command("roles/", Some("json"), true);
        assert!(cmd.contains("ansible-lint 'roles/'"));
        assert!(cmd.contains("--format 'json'"));
        assert!(cmd.contains("-p"));
    }

    #[test]
    fn test_validate_lint_target_ok() {
        assert!(AnsibleCommandBuilder::validate_lint_target("site.yml").is_ok());
        assert!(AnsibleCommandBuilder::validate_lint_target("roles/webserver").is_ok());
    }

    #[test]
    fn test_validate_lint_target_traversal() {
        assert!(AnsibleCommandBuilder::validate_lint_target("../../etc/passwd").is_err());
    }

    // ============== Vault Passthrough Tests ==============

    #[test]
    fn test_build_playbook_with_vault() {
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "site.yml",
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            None,
            Some("/etc/ansible/pass"),
            Some("prod@/etc/ansible/prod-pass"),
        );
        assert!(cmd.contains("--vault-password-file '/etc/ansible/pass'"));
        assert!(cmd.contains("--vault-id 'prod@/etc/ansible/prod-pass'"));
    }

    #[test]
    fn test_build_adhoc_with_vault() {
        let cmd = AnsibleCommandBuilder::build_adhoc_command(
            "all",
            "ping",
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            false,
            Some("/etc/ansible/pass"),
            Some("prod@/etc/ansible/prod-pass"),
        );
        assert!(cmd.contains("--vault-password-file '/etc/ansible/pass'"));
        assert!(cmd.contains("--vault-id 'prod@/etc/ansible/prod-pass'"));
    }

    // ============== Config Command Tests ==============

    #[test]
    fn test_build_config_minimal() {
        let cmd = AnsibleCommandBuilder::build_config_command(false, None);
        assert_eq!(cmd, "ansible-config dump");
    }

    #[test]
    fn test_build_config_only_changed_json() {
        let cmd = AnsibleCommandBuilder::build_config_command(true, Some("json"));
        assert!(cmd.contains("--only-changed"));
        assert!(cmd.contains("--format 'json'"));
    }
}
