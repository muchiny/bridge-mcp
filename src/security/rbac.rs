//! Role-Based Access Control (RBAC) for tool and host access
//!
//! Defines roles with allowed/denied tool patterns and host patterns.
//! Checked before tool execution to enforce access policies.
//!
//! # NOT WIRED
//!
//! `RbacEnforcer` is complete and unit-tested, but no production code path
//! calls it, and `validate_config` rejects `rbac.enabled: true` for that
//! reason (src/config/loader.rs). Wiring it requires a principal in the
//! request path, which does not exist today — see
//! docs/superpowers/plans/2026-08-18-audit-remediation.md, Wave 6.
//!
//! Do not delete this module: it is re-exported at `src/security/mod.rs:12`
//! and `rbac` is a field of `Config`, so every `Config { .. }` literal in the
//! tree — production and test alike — has to name it.
//!
//! (This line used to carry a count. It said 63 and was already wrong when
//! written; it is the kind of claim that rots on the next test added, which is
//! a poor thing to ship in the module documenting a security control that
//! enforced nothing.)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// RBAC configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RbacConfig {
    /// Whether RBAC is enabled (default: false for backward compatibility)
    #[serde(default)]
    pub enabled: bool,

    /// Default role assigned when no specific role matches
    #[serde(default = "default_role_name")]
    pub default_role: String,

    /// Role definitions
    #[serde(default)]
    pub roles: HashMap<String, Role>,
}

fn default_role_name() -> String {
    "default".to_string()
}

/// A role definition with access rules
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Role {
    /// Human-readable description
    #[serde(default)]
    pub description: Option<String>,

    /// Tool name patterns allowed (glob-style: `ssh_docker_*`, `*`)
    #[serde(default = "default_allow_all")]
    pub allowed_tools: Vec<String>,

    /// Tool name patterns explicitly denied (takes precedence over allowed)
    #[serde(default)]
    pub denied_tools: Vec<String>,

    /// Host name patterns allowed (glob-style: "prod-*", "*")
    #[serde(default = "default_allow_all")]
    pub allowed_hosts: Vec<String>,

    /// Host name patterns explicitly denied
    #[serde(default)]
    pub denied_hosts: Vec<String>,
}

fn default_allow_all() -> Vec<String> {
    vec!["*".to_string()]
}

impl Default for Role {
    fn default() -> Self {
        Self {
            description: None,
            allowed_tools: default_allow_all(),
            denied_tools: Vec::new(),
            allowed_hosts: default_allow_all(),
            denied_hosts: Vec::new(),
        }
    }
}

/// RBAC enforcer that checks access permissions
pub struct RbacEnforcer {
    config: RbacConfig,
}

impl RbacEnforcer {
    /// Create a new RBAC enforcer from configuration
    #[must_use]
    pub fn new(config: &RbacConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    /// Create a disabled enforcer (allows everything)
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            config: RbacConfig::default(),
        }
    }

    /// Check if a role is allowed to use a specific tool on a specific host
    #[must_use]
    pub fn is_allowed(&self, role: &str, tool_name: &str, host: &str) -> bool {
        if !self.config.enabled {
            return true;
        }

        let role_def = self
            .config
            .roles
            .get(role)
            .or_else(|| self.config.roles.get(&self.config.default_role));

        let Some(role_def) = role_def else {
            // No role definition found and no default - allow (backward compat)
            return true;
        };

        // Check tool access (denied takes precedence)
        if Self::matches_any(tool_name, &role_def.denied_tools) {
            return false;
        }
        if !Self::matches_any(tool_name, &role_def.allowed_tools) {
            return false;
        }

        // Check host access (denied takes precedence)
        if Self::matches_any(host, &role_def.denied_hosts) {
            return false;
        }
        if !Self::matches_any(host, &role_def.allowed_hosts) {
            return false;
        }

        true
    }

    /// Check if a string matches any of the glob patterns
    fn matches_any(value: &str, patterns: &[String]) -> bool {
        patterns
            .iter()
            .any(|pattern| Self::glob_match(pattern, value))
    }

    /// Simple glob matching supporting only '*' wildcard
    fn glob_match(pattern: &str, value: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        if let Some(prefix) = pattern.strip_suffix('*') {
            return value.starts_with(prefix);
        }

        if let Some(suffix) = pattern.strip_prefix('*') {
            return value.ends_with(suffix);
        }

        pattern == value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> RbacConfig {
        let mut roles = HashMap::new();
        roles.insert(
            "readonly".to_string(),
            Role {
                description: Some("Read-only access".to_string()),
                allowed_tools: vec![
                    "ssh_status".to_string(),
                    "ssh_metrics*".to_string(),
                    "ssh_ls".to_string(),
                ],
                denied_tools: vec![],
                allowed_hosts: vec!["*".to_string()],
                denied_hosts: vec![],
            },
        );
        roles.insert(
            "admin".to_string(),
            Role {
                description: Some("Full admin access".to_string()),
                allowed_tools: vec!["*".to_string()],
                denied_tools: vec![],
                allowed_hosts: vec!["prod-*".to_string(), "staging-*".to_string()],
                denied_hosts: vec![],
            },
        );
        roles.insert(
            "restricted".to_string(),
            Role {
                description: Some("Restricted access".to_string()),
                allowed_tools: vec!["*".to_string()],
                denied_tools: vec!["ssh_exec*".to_string(), "ssh_file_write".to_string()],
                allowed_hosts: vec!["dev-*".to_string()],
                denied_hosts: vec!["dev-secure".to_string()],
            },
        );

        RbacConfig {
            enabled: true,
            default_role: "readonly".to_string(),
            roles,
        }
    }

    #[test]
    fn test_disabled_allows_everything() {
        let enforcer = RbacEnforcer::disabled();
        assert!(enforcer.is_allowed("any", "ssh_exec", "any-host"));
    }

    #[test]
    fn test_readonly_role() {
        let enforcer = RbacEnforcer::new(&test_config());
        assert!(enforcer.is_allowed("readonly", "ssh_status", "any-host"));
        assert!(enforcer.is_allowed("readonly", "ssh_metrics", "prod-1"));
        assert!(enforcer.is_allowed("readonly", "ssh_metrics_multi", "prod-1"));
        assert!(enforcer.is_allowed("readonly", "ssh_ls", "dev-1"));
        assert!(!enforcer.is_allowed("readonly", "ssh_exec", "any-host"));
        assert!(!enforcer.is_allowed("readonly", "ssh_docker_ps", "any-host"));
    }

    #[test]
    fn test_admin_role_host_restriction() {
        let enforcer = RbacEnforcer::new(&test_config());
        assert!(enforcer.is_allowed("admin", "ssh_exec", "prod-web1"));
        assert!(enforcer.is_allowed("admin", "ssh_exec", "staging-db1"));
        assert!(!enforcer.is_allowed("admin", "ssh_exec", "dev-web1"));
    }

    #[test]
    fn test_denied_takes_precedence() {
        let enforcer = RbacEnforcer::new(&test_config());
        assert!(!enforcer.is_allowed("restricted", "ssh_exec", "dev-web1"));
        assert!(!enforcer.is_allowed("restricted", "ssh_exec_multi", "dev-web1"));
        assert!(!enforcer.is_allowed("restricted", "ssh_file_write", "dev-web1"));
        assert!(enforcer.is_allowed("restricted", "ssh_file_read", "dev-web1"));
    }

    #[test]
    fn test_denied_host_takes_precedence() {
        let enforcer = RbacEnforcer::new(&test_config());
        assert!(enforcer.is_allowed("restricted", "ssh_ls", "dev-web1"));
        assert!(!enforcer.is_allowed("restricted", "ssh_ls", "dev-secure"));
    }

    #[test]
    fn test_unknown_role_uses_default() {
        let enforcer = RbacEnforcer::new(&test_config());
        // Unknown role falls back to "readonly" default
        assert!(enforcer.is_allowed("unknown_role", "ssh_status", "any-host"));
        assert!(!enforcer.is_allowed("unknown_role", "ssh_exec", "any-host"));
    }

    #[test]
    fn test_glob_match() {
        assert!(RbacEnforcer::glob_match("*", "anything"));
        assert!(RbacEnforcer::glob_match("ssh_docker_*", "ssh_docker_ps"));
        assert!(RbacEnforcer::glob_match("ssh_docker_*", "ssh_docker_logs"));
        assert!(!RbacEnforcer::glob_match("ssh_docker_*", "ssh_k8s_get"));
        assert!(RbacEnforcer::glob_match("*_status", "ssh_status"));
        assert!(RbacEnforcer::glob_match("exact_match", "exact_match"));
        assert!(!RbacEnforcer::glob_match("exact_match", "not_exact_match"));
    }

    // ============== Tests to catch previously-missed mutations ==============

    #[test]
    fn test_default_role_name_value() {
        assert_eq!(
            default_role_name(),
            "default",
            "default_role_name must return 'default'"
        );
    }

    #[test]
    fn test_default_allow_all_value() {
        let result = default_allow_all();
        assert_eq!(
            result,
            vec!["*".to_string()],
            "default_allow_all must return vec![\"*\"]"
        );
    }

    #[test]
    fn test_default_role_has_wildcard_access() {
        let role = Role::default();
        assert_eq!(role.allowed_tools, vec!["*"]);
        assert_eq!(role.allowed_hosts, vec!["*"]);
        assert!(role.denied_tools.is_empty());
        assert!(role.denied_hosts.is_empty());
    }

    #[test]
    fn test_rbac_config_deserialize_uses_defaults() {
        let yaml = r"
enabled: true
roles:
  admin:
    description: Full access
";
        let config: RbacConfig = serde_saphyr::from_str(yaml).unwrap();
        assert_eq!(config.default_role, "default");
        let admin = config.roles.get("admin").unwrap();
        assert_eq!(admin.allowed_tools, vec!["*"]);
        assert_eq!(admin.allowed_hosts, vec!["*"]);
    }
}
