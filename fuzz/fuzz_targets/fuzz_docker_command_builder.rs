#![no_main]
use bridge_mcp_fuzz::assert_arrives_as_text;
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::docker::DockerCommandBuilder;

// This target used to assert only the PROGRAM NAME: `assert!(cmd.contains(
// "the program name"))`. That is a string the builder writes itself, in every branch,
// whatever the caller passed — so NO INPUT COULD EVER FAIL IT. A builder that
// pastes `data` into the command line in bare does not panic and does not drop
// the program name; it produces a dangerous command and the target stays
// green. An echo, not a property.
//
// What it asserts now: whatever the builder ACCEPTED arrives in the command as
// TEXT — inside one literal run, having contributed no shell syntax. Refusal
// is always fine; the fuzzer is looking for values that get THROUGH.
//
// `assert_arrives_as_text` rather than `assert_survives_as_one_word`: these
// builders emit pipelines and `&&` chains of their own, and an oracle that
// refuses every operator would be red on healthy code. It is `contains` on the
// literal run rather than equality because a value legitimately lands inside a
// larger word (`--filter=name=VALUE`); an operator still splits the run either
// way, which is what the assertion is for.
//
// Run with the dictionary or this explores very little:
// `cargo +nightly fuzz run fuzz_docker_command_builder -- -dict=fuzz/dicts/shell.dict`

fuzz_target!(|data: &str| {
    let env = vec![data.to_string()];
    let containers = vec![data.to_string()];
    let services = vec![data.to_string()];

    // ps
    let cmd = DockerCommandBuilder::build_ps_command(Some("docker"), true, Some(data), Some(data));
    assert_arrives_as_text(&cmd, data, "ps");

    // logs
    let cmd = DockerCommandBuilder::build_logs_command(
        Some("docker"),
        data,
        Some(100),
        Some(data),
        Some(data),
        true,
    );
    assert_arrives_as_text(&cmd, data, "logs");

    // inspect
    let cmd = DockerCommandBuilder::build_inspect_command(Some("docker"), data, Some(data));
    assert_arrives_as_text(&cmd, data, "inspect");

    // exec
    let cmd = DockerCommandBuilder::build_exec_command(
        Some("docker"),
        data,
        data,
        Some(data),
        Some(data),
        Some(&env),
    );
    assert_arrives_as_text(&cmd, data, "exec");

    // images
    let cmd =
        DockerCommandBuilder::build_images_command(Some("docker"), true, Some(data), Some(data));
    assert_arrives_as_text(&cmd, data, "images");

    // stats
    let cmd = DockerCommandBuilder::build_stats_command(
        Some("docker"),
        Some(&containers),
        true,
        Some(data),
    );
    assert_arrives_as_text(&cmd, data, "stats");

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
    assert_arrives_as_text(&cmd, data, "compose");

    // volume ls
    let cmd =
        DockerCommandBuilder::build_volume_ls_command(Some("docker"), Some(data), Some(data));
    assert_arrives_as_text(&cmd, data, "volume_ls");

    // network ls
    let cmd =
        DockerCommandBuilder::build_network_ls_command(Some("docker"), Some(data), Some(data));
    assert_arrives_as_text(&cmd, data, "network_ls");

    // volume inspect
    let cmd =
        DockerCommandBuilder::build_volume_inspect_command(Some("docker"), data, Some(data));
    assert_arrives_as_text(&cmd, data, "volume_inspect");

    // network inspect
    let cmd =
        DockerCommandBuilder::build_network_inspect_command(Some("docker"), data, Some(data));
    assert_arrives_as_text(&cmd, data, "network_inspect");

    // validate_compose_action
    let _ = DockerCommandBuilder::validate_compose_action(data);
});
