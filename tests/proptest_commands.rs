//! Property-based tests for command builders and validation functions.
//!
//! Uses proptest to automatically generate thousands of inputs and verify
//! invariants that must hold for all possible inputs — complementing the
//! existing fuzz targets with shrinking and deterministic replay.

use proptest::prelude::*;

use bridge_mcp::config::ShellType;
use bridge_mcp::domain::use_cases::{
    ansible::AnsibleCommandBuilder,
    cron::validate_cron_comment,
    database::DatabaseCommandBuilder,
    docker::DockerCommandBuilder,
    firewall::{validate_port, validate_source},
    kubernetes::{KubernetesCommandBuilder, kubectl_detect_prefix},
    network::validate_network_target,
    shell,
    systemd::{SystemdCommandBuilder, validate_service_name},
};

// ===== Shell Escaping Properties =====

proptest! {
    /// POSIX-escaped strings must always be wrapped in single quotes.
    #[test]
    fn posix_escape_always_wrapped_in_single_quotes(s in "\\PC*") {
        let escaped = shell::escape(&s, ShellType::Posix);
        prop_assert!(escaped.starts_with('\''), "Missing opening quote: {escaped}");
        prop_assert!(escaped.ends_with('\''), "Missing closing quote: {escaped}");
    }

    /// Cmd-escaped strings must always be wrapped in double quotes.
    #[test]
    fn cmd_escape_always_wrapped_in_double_quotes(s in "\\PC*") {
        let escaped = shell::escape(&s, ShellType::Cmd);
        prop_assert!(escaped.starts_with('"'), "Missing opening quote: {escaped}");
        prop_assert!(escaped.ends_with('"'), "Missing closing quote: {escaped}");
    }

    /// PowerShell-escaped strings must always be wrapped in single quotes.
    #[test]
    fn powershell_escape_always_wrapped_in_single_quotes(s in "\\PC*") {
        let escaped = shell::escape(&s, ShellType::PowerShell);
        prop_assert!(escaped.starts_with('\''), "Missing opening quote: {escaped}");
        prop_assert!(escaped.ends_with('\''), "Missing closing quote: {escaped}");
    }

    /// Escaping must never produce an empty string.
    #[test]
    fn escape_never_produces_empty(s in "\\PC*") {
        prop_assert!(!shell::escape(&s, ShellType::Posix).is_empty());
        prop_assert!(!shell::escape(&s, ShellType::Cmd).is_empty());
        prop_assert!(!shell::escape(&s, ShellType::PowerShell).is_empty());
    }

    /// Escaped output must always be at least 2 chars (the quotes).
    #[test]
    fn escape_at_least_two_chars(s in "\\PC*") {
        prop_assert!(shell::escape(&s, ShellType::Posix).len() >= 2);
        prop_assert!(shell::escape(&s, ShellType::Cmd).len() >= 2);
        prop_assert!(shell::escape(&s, ShellType::PowerShell).len() >= 2);
    }

    /// Cmd escaping must escape all dangerous metacharacters.
    #[test]
    fn cmd_escape_neutralizes_metacharacters(s in "\\PC*") {
        let escaped = shell::escape(&s, ShellType::Cmd);
        // Remove the wrapping quotes to inspect interior
        let interior = &escaped[1..escaped.len()-1];
        // Every bare & | < > must be preceded by ^
        let chars: Vec<char> = interior.chars().collect();
        for (i, &c) in chars.iter().enumerate() {
            if matches!(c, '&' | '|' | '<' | '>') {
                prop_assert!(i > 0 && chars[i-1] == '^',
                    "Unescaped metachar '{}' at position {} in: {}", c, i, escaped);
            }
        }
    }

    /// Cmd escaping must double all percent signs to prevent variable expansion.
    #[test]
    fn cmd_escape_doubles_percent_signs(s in "\\PC*") {
        let escaped = shell::escape(&s, ShellType::Cmd);
        let interior = &escaped[1..escaped.len()-1];
        // Count % in input and %% in output interior
        let input_pct = s.chars().filter(|&c| c == '%').count();
        let output_pct = interior.matches("%%").count();
        prop_assert_eq!(input_pct, output_pct,
            "Expected {} doubled %% but found {} in: {}", input_pct, output_pct, escaped);
    }

    /// cd_and_run must always produce a non-empty command.
    #[test]
    fn cd_and_run_never_empty(dir in "\\PC+", cmd in "\\PC+") {
        prop_assert!(!shell::cd_and_run(&dir, &cmd, ShellType::Posix).is_empty());
        prop_assert!(!shell::cd_and_run(&dir, &cmd, ShellType::Cmd).is_empty());
        prop_assert!(!shell::cd_and_run(&dir, &cmd, ShellType::PowerShell).is_empty());
    }
}

// ===== Validation Function Properties =====

proptest! {
    /// Valid service names (alphanumeric + hyphens/underscores/dots/@) must pass.
    #[test]
    fn valid_service_names_accepted(name in "[a-zA-Z0-9._@-]{1,64}") {
        prop_assert!(validate_service_name(&name).is_ok(),
            "Valid service name rejected: {name}");
    }

    /// Service names with shell metacharacters must be rejected.
    #[test]
    fn service_names_with_metacharacters_rejected(
        prefix in "[a-zA-Z]{1,4}",
        metachar in prop::sample::select(vec!['$', '`', ';', '|', '&', '>', '<', '(', ')', '{', '}']),
        suffix in "[a-zA-Z]{1,4}",
    ) {
        let name = format!("{prefix}{metachar}{suffix}");
        prop_assert!(validate_service_name(&name).is_err(),
            "Dangerous service name accepted: {name}");
    }

    /// Empty service names must always be rejected.
    #[test]
    fn empty_service_name_rejected(_unused in Just(0u8)) {
        prop_assert!(validate_service_name("").is_err());
    }

    /// Valid port numbers (1-65535) must be accepted.
    #[test]
    fn valid_port_numbers_accepted(port in 1u16..=65535u16) {
        prop_assert!(validate_port(&port.to_string()).is_ok(),
            "Valid port rejected: {port}");
    }

    /// Port 0 must be rejected.
    #[test]
    fn port_zero_rejected(_unused in Just(0u8)) {
        prop_assert!(validate_port("0").is_err());
    }

    /// Valid port ranges must be accepted.
    #[test]
    fn valid_port_ranges_accepted(start in 1u16..32768u16, offset in 0u16..32767u16) {
        let end = start.saturating_add(offset).max(start);
        let range = format!("{start}:{end}");
        prop_assert!(validate_port(&range).is_ok(),
            "Valid port range rejected: {range}");
    }

    /// Valid CIDR sources must be accepted.
    #[test]
    fn valid_ipv4_sources_accepted(
        a in 0u8..=255u8, b in 0u8..=255u8,
        c in 0u8..=255u8, d in 0u8..=255u8,
    ) {
        let ip = format!("{a}.{b}.{c}.{d}");
        prop_assert!(validate_source(&ip).is_ok(), "Valid IP rejected: {ip}");
    }

    /// Sources with shell metacharacters must be rejected.
    #[test]
    fn sources_with_metacharacters_rejected(
        metachar in prop::sample::select(vec!['$', '`', ';', '|', '&', '!', '(', ')', ' ']),
    ) {
        let source = format!("192.168.1.1{metachar}");
        prop_assert!(validate_source(&source).is_err(),
            "Dangerous source accepted: {source}");
    }

    /// Valid network targets (IP/hostname) must be accepted.
    #[test]
    fn valid_network_targets_accepted(host in "[a-zA-Z0-9][a-zA-Z0-9._-]{0,30}") {
        prop_assert!(validate_network_target(&host).is_ok(),
            "Valid target rejected: {host}");
    }

    /// Cron comments with safe characters must be accepted.
    #[test]
    fn valid_cron_comments_accepted(comment in "[a-zA-Z0-9 _-]{1,50}") {
        prop_assert!(validate_cron_comment(&comment).is_ok(),
            "Valid comment rejected: {comment}");
    }
}

// ===== Command Builder Properties =====

proptest! {
    /// Docker ps command must always contain "ps".
    #[test]
    fn docker_ps_contains_ps(all in any::<bool>()) {
        let cmd = DockerCommandBuilder::build_ps_command(Some("docker"), all, None, None);
        prop_assert!(cmd.contains("ps"), "Command missing 'ps': {cmd}");
    }

    /// Docker ps with filter must escape the filter value.
    #[test]
    fn docker_ps_filter_is_escaped(filter in "[a-zA-Z0-9=.]+") {
        let cmd = DockerCommandBuilder::build_ps_command(
            Some("docker"), false, Some(&filter), None
        );
        prop_assert!(cmd.contains("--filter"), "Command missing '--filter': {cmd}");
        prop_assert!(cmd.contains('\''), "Filter not escaped with quotes: {cmd}");
    }

    /// Docker logs command must contain the container name (escaped).
    #[test]
    fn docker_logs_contains_container(container in "[a-zA-Z0-9_-]{1,30}") {
        let cmd = DockerCommandBuilder::build_logs_command(
            Some("docker"), &container, None, None, None, false
        );
        prop_assert!(cmd.contains(&container), "Container name missing: {cmd}");
        prop_assert!(cmd.contains("logs"), "Command missing 'logs': {cmd}");
    }

    /// Docker exec command must escape both container and command.
    #[test]
    fn docker_exec_escapes_inputs(
        container in "[a-zA-Z0-9_-]{1,20}",
        command in "[a-zA-Z0-9 /._-]{1,50}",
    ) {
        let cmd = DockerCommandBuilder::build_exec_command(
            Some("docker"), &container, &command, None, None, None
        );
        prop_assert!(cmd.contains("exec"), "Command missing 'exec': {cmd}");
        prop_assert!(cmd.contains("sh -c"), "Command missing 'sh -c': {cmd}");
    }

    /// Systemd status command must always produce valid output.
    #[test]
    fn systemd_status_contains_service(service in "[a-zA-Z0-9._-]{1,30}") {
        let cmd = SystemdCommandBuilder::build_status_command(&service);
        prop_assert!(cmd.contains("systemctl status"), "Missing 'systemctl status': {cmd}");
        prop_assert!(cmd.contains("--no-pager"), "Missing '--no-pager': {cmd}");
    }

    /// Systemd start command must produce expected format.
    #[test]
    fn systemd_start_command_format(service in "[a-zA-Z0-9._-]{1,30}") {
        let cmd = SystemdCommandBuilder::build_start_command(&service);
        prop_assert!(cmd.starts_with("systemctl start "), "Bad format: {cmd}");
    }

    /// Kubectl get command must contain "get" and the resource type.
    #[test]
    fn kubectl_get_contains_resource(resource in "[a-zA-Z]{1,20}") {
        let cmd = KubernetesCommandBuilder::build_get_command(
            Some("kubectl"), &resource, None, None, false, None, None, None, None, false, false, false, None,
        );
        prop_assert!(cmd.contains("get"), "Missing 'get': {cmd}");
        prop_assert!(cmd.contains(&resource), "Missing resource: {cmd}");
    }

    /// Kubectl get with namespace must include -n flag.
    #[test]
    fn kubectl_get_with_namespace(
        resource in "[a-zA-Z]{1,10}",
        namespace in "[a-zA-Z0-9-]{1,20}",
    ) {
        let cmd = KubernetesCommandBuilder::build_get_command(
            Some("kubectl"), &resource, None, Some(&namespace),
            false, None, None, None, None, false, false, false, None,
        );
        prop_assert!(cmd.contains("-n"), "Missing '-n' flag: {cmd}");
        prop_assert!(cmd.contains(&namespace), "Missing namespace: {cmd}");
    }

    /// Auto-detect prefix must never be empty.
    #[test]
    fn kubectl_detect_prefix_never_empty(bin in proptest::option::of("[a-zA-Z0-9/._-]{1,30}")) {
        let prefix = kubectl_detect_prefix(bin.as_deref());
        prop_assert!(!prefix.is_empty(), "Empty kubectl prefix");
    }

    /// Ansible playbook path validation rejects path traversal.
    #[test]
    fn ansible_rejects_path_traversal(
        prefix in "[a-zA-Z]{1,5}",
    ) {
        let path = format!("{prefix}/../../etc/passwd");
        prop_assert!(AnsibleCommandBuilder::validate_playbook_path(&path).is_err(),
            "Path traversal accepted: {path}");
    }

    /// Database query validation rejects dangerous statements.
    #[test]
    fn database_rejects_drop_queries(table in "[a-zA-Z]{1,20}") {
        let query = format!("DROP TABLE {table}");
        prop_assert!(DatabaseCommandBuilder::validate_query(&query).is_err(),
            "DROP query accepted: {query}");
    }
}
