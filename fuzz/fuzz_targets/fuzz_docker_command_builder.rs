#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::docker::DockerCommandBuilder;

fuzz_target!(|data: &str| {
    let env = vec![data.to_string()];
    let containers = vec![data.to_string()];
    let services = vec![data.to_string()];

    // ps
    let cmd = DockerCommandBuilder::build_ps_command(Some("docker"), true, Some(data), Some(data));
    assert!(cmd.contains("docker"), "ps must contain 'docker': {cmd}");

    // logs
    let cmd = DockerCommandBuilder::build_logs_command(
        Some("docker"),
        data,
        Some(100),
        Some(data),
        Some(data),
        true,
    );
    assert!(cmd.contains("docker"), "logs must contain 'docker': {cmd}");

    // inspect
    let cmd = DockerCommandBuilder::build_inspect_command(Some("docker"), data, Some(data));
    assert!(cmd.contains("docker"), "inspect must contain 'docker': {cmd}");

    // exec
    let cmd = DockerCommandBuilder::build_exec_command(
        Some("docker"),
        data,
        data,
        Some(data),
        Some(data),
        Some(&env),
    );
    assert!(cmd.contains("docker"), "exec must contain 'docker': {cmd}");

    // images
    let cmd =
        DockerCommandBuilder::build_images_command(Some("docker"), true, Some(data), Some(data));
    assert!(cmd.contains("docker"), "images must contain 'docker': {cmd}");

    // stats
    let cmd = DockerCommandBuilder::build_stats_command(
        Some("docker"),
        Some(&containers),
        true,
        Some(data),
    );
    assert!(cmd.contains("docker"), "stats must contain 'docker': {cmd}");

    // compose
    let cmd = DockerCommandBuilder::build_compose_command(
        Some("docker compose"),
        "up",
        data,
        Some(data),
        Some(&services),
        true,
        true,
        Some(60),
    );
    assert!(
        cmd.contains("docker compose"),
        "compose must contain 'docker compose': {cmd}"
    );

    // volume ls
    let cmd =
        DockerCommandBuilder::build_volume_ls_command(Some("docker"), Some(data), Some(data));
    assert!(
        cmd.contains("docker"),
        "volume_ls must contain 'docker': {cmd}"
    );

    // network ls
    let cmd =
        DockerCommandBuilder::build_network_ls_command(Some("docker"), Some(data), Some(data));
    assert!(
        cmd.contains("docker"),
        "network_ls must contain 'docker': {cmd}"
    );

    // volume inspect
    let cmd =
        DockerCommandBuilder::build_volume_inspect_command(Some("docker"), data, Some(data));
    assert!(
        cmd.contains("docker"),
        "volume_inspect must contain 'docker': {cmd}"
    );

    // network inspect
    let cmd =
        DockerCommandBuilder::build_network_inspect_command(Some("docker"), data, Some(data));
    assert!(
        cmd.contains("docker"),
        "network_inspect must contain 'docker': {cmd}"
    );

    // validate_compose_action
    let _ = DockerCommandBuilder::validate_compose_action(data);
});
