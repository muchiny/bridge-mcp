//! Tool Registry Filtering Integration Tests
//!
//! Tests that `ToolGroupsConfig` properly controls which tools are visible
//! and callable through the registry.

use bridge_mcp::config::ToolGroupsConfig;
use bridge_mcp::mcp::registry::{
    all_enabled_tool_groups_config_for_test, create_filtered_registry, tool_annotations, tool_group,
};

// ============== Default Registry ==============

#[test]
fn test_default_registry_includes_all_groups() {
    let config = all_enabled_tool_groups_config_for_test();
    let registry = create_filtered_registry(&config);

    let tools = registry.list_tools();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();

    // Core tools always present
    assert!(names.contains(&"ssh_exec"), "core tools should be present");
    assert!(
        names.contains(&"ssh_status"),
        "core tools should be present"
    );
    assert!(
        names.contains(&"ssh_history"),
        "core tools should be present"
    );

    // Various group tools present
    assert!(
        names.contains(&"ssh_docker_ps"),
        "docker tools should be present"
    );
    assert!(
        names.contains(&"ssh_k8s_get"),
        "kubernetes tools should be present"
    );
    assert!(
        names.contains(&"ssh_service_status"),
        "systemd tools should be present"
    );
    assert!(
        names.contains(&"ssh_win_service_list"),
        "windows tools should be present"
    );
}

// ============== Disable Single Group ==============

#[test]
fn test_disable_docker_removes_all_docker_tools() {
    let mut groups = all_enabled_tool_groups_config_for_test().groups;
    groups.insert("docker".to_string(), false);
    let config = ToolGroupsConfig { groups };
    let registry = create_filtered_registry(&config);

    let tools = registry.list_tools();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();

    // No docker tools
    assert!(
        !names.contains(&"ssh_docker_ps"),
        "docker_ps should be gone"
    );
    assert!(
        !names.contains(&"ssh_docker_logs"),
        "docker_logs should be gone"
    );
    assert!(
        !names.contains(&"ssh_docker_inspect"),
        "docker_inspect should be gone"
    );
    assert!(
        !names.contains(&"ssh_docker_exec"),
        "docker_exec should be gone"
    );
    assert!(
        !names.contains(&"ssh_docker_compose"),
        "docker_compose should be gone"
    );
    assert!(
        !names.contains(&"ssh_docker_images"),
        "docker_images should be gone"
    );
    assert!(
        !names.contains(&"ssh_docker_stats"),
        "docker_stats should be gone"
    );
    assert!(
        !names.contains(&"ssh_docker_volume_ls"),
        "docker_volume_ls should be gone"
    );
    assert!(
        !names.contains(&"ssh_docker_network_ls"),
        "docker_network_ls should be gone"
    );

    // Other groups unaffected
    assert!(names.contains(&"ssh_exec"), "core should still be present");
    assert!(
        names.contains(&"ssh_k8s_get"),
        "kubernetes should still be present"
    );
}

#[test]
fn test_disable_kubernetes_removes_all_k8s_and_helm_tools() {
    let mut groups = all_enabled_tool_groups_config_for_test().groups;
    groups.insert("kubernetes".to_string(), false);
    let config = ToolGroupsConfig { groups };
    let registry = create_filtered_registry(&config);

    let tools = registry.list_tools();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();

    // No kubernetes or helm tools
    for tool in &[
        "ssh_k8s_get",
        "ssh_k8s_logs",
        "ssh_k8s_describe",
        "ssh_k8s_apply",
        "ssh_k8s_delete",
        "ssh_k8s_rollout",
        "ssh_k8s_scale",
        "ssh_k8s_exec",
        "ssh_k8s_top",
        "ssh_helm_list",
        "ssh_helm_status",
        "ssh_helm_upgrade",
        "ssh_helm_install",
        "ssh_helm_rollback",
        "ssh_helm_history",
        "ssh_helm_uninstall",
    ] {
        assert!(!names.contains(tool), "{tool} should be gone");
    }
}

// ============== Disable Multiple Groups ==============

#[test]
fn test_disable_multiple_groups_removes_all_their_tools() {
    let mut groups = all_enabled_tool_groups_config_for_test().groups;
    groups.insert("docker".to_string(), false);
    groups.insert("kubernetes".to_string(), false);
    groups.insert("ansible".to_string(), false);
    let config = ToolGroupsConfig { groups };
    let registry = create_filtered_registry(&config);

    let tools = registry.list_tools();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();

    assert!(!names.contains(&"ssh_docker_ps"));
    assert!(!names.contains(&"ssh_k8s_get"));
    assert!(!names.contains(&"ssh_ansible_playbook"));

    // Core still present
    assert!(names.contains(&"ssh_exec"));
    assert!(names.contains(&"ssh_status"));
}

// ============== Disable Windows Groups ==============

#[test]
fn test_disable_all_windows_groups() {
    let mut groups = all_enabled_tool_groups_config_for_test().groups;
    for group in &[
        "windows_services",
        "windows_events",
        "active_directory",
        "scheduled_tasks",
        "windows_firewall",
        "iis",
        "windows_updates",
        "windows_perf",
        "hyperv",
        "windows_registry",
        "windows_features",
        "windows_network",
        "windows_process",
    ] {
        groups.insert((*group).to_string(), false);
    }
    let config = ToolGroupsConfig { groups };
    let registry = create_filtered_registry(&config);

    let tools = registry.list_tools();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();

    // No windows tools
    for name in &names {
        assert!(
            !name.starts_with("ssh_win_")
                && !name.starts_with("ssh_ad_")
                && !name.starts_with("ssh_schtask_")
                && !name.starts_with("ssh_iis_")
                && !name.starts_with("ssh_hyperv_")
                && !name.starts_with("ssh_reg_"),
            "Windows tool {name} should be gone"
        );
    }

    // Linux tools still present
    assert!(names.contains(&"ssh_exec"));
    assert!(names.contains(&"ssh_docker_ps"));
    assert!(names.contains(&"ssh_service_status"));
}

// ============== Tool Group Mapping Completeness ==============

#[test]
fn test_every_tool_maps_to_a_known_group() {
    let config = all_enabled_tool_groups_config_for_test();
    let registry = create_filtered_registry(&config);
    let tools = registry.list_tools();

    let known_groups = [
        "core",
        "config",
        "file_transfer",
        "sessions",
        "monitoring",
        "tunnels",
        "directory",
        "database",
        "backup",
        "docker",
        "esxi",
        "git",
        "kubernetes",
        "cri",
        "k3s",
        "ansible",
        "systemd",
        "network",
        "process",
        "package",
        "firewall",
        "cron",
        "certificates",
        "nginx",
        "redis",
        "terraform",
        "vault",
        "windows_services",
        "windows_events",
        "active_directory",
        "scheduled_tasks",
        "windows_firewall",
        "iis",
        "windows_updates",
        "windows_perf",
        "hyperv",
        "windows_registry",
        "windows_features",
        "windows_network",
        "windows_process",
        "cron_analysis",
        "performance",
        "container_logs",
        "network_security",
        "compliance",
        "alerting",
        "capacity",
        "incident",
        "log_aggregation",
        "key_management",
        "chatops",
        "templates",
        "pty",
        "cloud",
        "inventory",
        "multicloud",
        "diagnostics",
        "runbooks",
        "recording",
        "orchestration",
        "drift",
        "security_scan",
        "file_ops",
        "user_management",
        "storage",
        "journald",
        "systemd_timers",
        "security_modules",
        "network_equipment",
        "podman",
        "ldap",
        "postgresql",
        "mysql",
        "apache",
        "letsencrypt",
        "mongodb",
        "awx",
    ];

    for tool in &tools {
        let group = tool_group(&tool.name);
        assert!(
            known_groups.contains(&group),
            "Tool '{}' maps to unknown group '{}'",
            tool.name,
            group
        );
    }
}

// ============== Annotation Completeness ==============

#[test]
fn test_every_tool_has_non_empty_annotations() {
    let config = all_enabled_tool_groups_config_for_test();
    let registry = create_filtered_registry(&config);
    let tools = registry.list_tools();

    for tool in &tools {
        let ann = tool_annotations(&tool.name);
        assert!(
            ann.title.is_some(),
            "Tool '{}' should have a title annotation",
            tool.name
        );
    }
}

#[test]
fn test_read_only_tools_not_marked_destructive() {
    let config = all_enabled_tool_groups_config_for_test();
    let registry = create_filtered_registry(&config);
    let tools = registry.list_tools();

    for tool in &tools {
        let ann = tool_annotations(&tool.name);
        if ann.read_only_hint == Some(true) {
            assert_ne!(
                ann.destructive_hint,
                Some(true),
                "Tool '{}' cannot be both read-only and destructive",
                tool.name
            );
        }
    }
}

#[test]
fn test_destructive_tools_not_marked_read_only() {
    let config = all_enabled_tool_groups_config_for_test();
    let registry = create_filtered_registry(&config);
    let tools = registry.list_tools();

    for tool in &tools {
        let ann = tool_annotations(&tool.name);
        if ann.destructive_hint == Some(true) {
            assert_ne!(
                ann.read_only_hint,
                Some(true),
                "Tool '{}' cannot be both destructive and read-only",
                tool.name
            );
        }
    }
}

// ============== Task Execution Field ==============

#[test]
fn test_every_tool_has_execution_task_support() {
    let config = all_enabled_tool_groups_config_for_test();
    let registry = create_filtered_registry(&config);
    let tools = registry.list_tools();

    for tool in &tools {
        assert!(
            tool.execution.is_some(),
            "Tool '{}' should have an execution field",
            tool.name
        );
        assert_eq!(
            tool.execution.as_ref().unwrap().task_support,
            "optional",
            "Tool '{}' should have taskSupport: \"optional\"",
            tool.name
        );
    }
}

// ============== Schema Validity ==============

#[test]
fn test_all_tools_have_valid_input_schema() {
    let config = all_enabled_tool_groups_config_for_test();
    let registry = create_filtered_registry(&config);
    let tools = registry.list_tools();

    for tool in &tools {
        assert!(!tool.name.is_empty(), "Tool name should not be empty");
        assert!(
            !tool.description.is_empty(),
            "Tool '{}' should have a description",
            tool.name
        );
        assert!(
            tool.input_schema.is_object(),
            "Tool '{}' should have object input_schema",
            tool.name
        );
    }
}

// ============== Calling Disabled Tool ==============

#[tokio::test]
async fn test_calling_disabled_tool_returns_unknown_tool_error() {
    let mut groups = all_enabled_tool_groups_config_for_test().groups;
    groups.insert("docker".to_string(), false);
    let config = ToolGroupsConfig { groups };
    let registry = create_filtered_registry(&config);

    // ssh_docker_ps should not exist in the registry
    let handler = registry.get("ssh_docker_ps");
    assert!(
        handler.is_none(),
        "Disabled tool should not be in the registry"
    );
}

#[test]
fn test_enabled_tool_is_accessible() {
    let config = all_enabled_tool_groups_config_for_test();
    let registry = create_filtered_registry(&config);

    let handler = registry.get("ssh_exec");
    assert!(handler.is_some(), "Enabled tool should be in the registry");
}
