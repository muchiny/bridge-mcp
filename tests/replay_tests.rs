//! Deterministic Session Replay Tests
//!
//! Replays recorded SSH sessions from JSON fixture files, enabling
//! reproducible testing without real SSH infrastructure.
//!
//! Fixture format: array of `{command, stdout, stderr, exit_code, duration_ms}` objects.
//! Uses fixture data to validate command output parsing, exit code handling,
//! and multi-step workflow correctness.

use std::collections::HashMap;
use std::path::Path;

/// A recorded command-response pair from a real SSH session.
#[derive(serde::Deserialize, Debug, Clone)]
struct RecordedExchange {
    command: String,
    stdout: String,
    stderr: String,
    exit_code: i32,
    #[allow(dead_code)]
    duration_ms: u64,
}

/// Load a fixture file and return the recorded exchanges.
fn load_fixture(fixture_name: &str) -> Vec<RecordedExchange> {
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(fixture_name);
    let content = std::fs::read_to_string(&fixture_path)
        .unwrap_or_else(|e| panic!("Failed to read fixture {}: {e}", fixture_path.display()));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse fixture {}: {e}", fixture_path.display()))
}

/// Build a lookup map from command to response.
fn build_response_map(exchanges: &[RecordedExchange]) -> HashMap<&str, &RecordedExchange> {
    exchanges.iter().map(|e| (e.command.as_str(), e)).collect()
}

// ─── Basic commands replay ─────────────────────────────────────────

#[test]
fn replay_basic_commands_all_have_valid_structure() {
    let exchanges = load_fixture("basic_commands.json");

    for exchange in &exchanges {
        assert!(!exchange.command.is_empty(), "Command must not be empty");
        // stdout and stderr can be empty
        // exit_code 0 = success, non-zero = error
        assert!(
            exchange.exit_code >= 0,
            "Exit code should be non-negative for command: {}",
            exchange.command
        );
    }
}

#[test]
fn replay_basic_commands_successful_commands() {
    let exchanges = load_fixture("basic_commands.json");
    let responses = build_response_map(&exchanges);

    // whoami returns current user
    let whoami = responses["whoami"];
    assert_eq!(whoami.exit_code, 0);
    assert_eq!(whoami.stdout.trim(), "deploy");

    // pwd returns working directory
    let pwd = responses["pwd"];
    assert_eq!(pwd.exit_code, 0);
    assert_eq!(pwd.stdout.trim(), "/home/deploy");

    // uname returns kernel info
    let uname = responses["uname -a"];
    assert_eq!(uname.exit_code, 0);
    assert!(uname.stdout.contains("Linux"));
}

#[test]
fn replay_basic_commands_error_handling() {
    let exchanges = load_fixture("basic_commands.json");
    let responses = build_response_map(&exchanges);

    // cat nonexistent file returns error
    let cat_err = responses["cat /nonexistent"];
    assert_eq!(cat_err.exit_code, 1);
    assert_eq!(cat_err.stdout, "");
    assert!(cat_err.stderr.contains("No such file or directory"));
}

#[test]
fn replay_basic_commands_ls_output_parsing() {
    let exchanges = load_fixture("basic_commands.json");
    let responses = build_response_map(&exchanges);

    let ls = responses["ls -la /tmp"];
    assert_eq!(ls.exit_code, 0);

    let lines: Vec<&str> = ls.stdout.lines().collect();
    // Should have header + entries
    assert!(lines.len() >= 3, "ls -la should have multiple lines");
    assert!(lines[0].starts_with("total"), "First line should be total");
}

// ─── Docker workflow replay ────────────────────────────────────────

#[test]
fn replay_docker_binary_detection() {
    let exchanges = load_fixture("docker_workflow.json");
    let responses = build_response_map(&exchanges);

    let detect = responses["command -v docker || command -v podman"];
    assert_eq!(detect.exit_code, 0);
    assert!(detect.stdout.contains("docker"));
}

#[test]
fn replay_docker_container_listing() {
    let exchanges = load_fixture("docker_workflow.json");
    let responses = build_response_map(&exchanges);

    let ps = responses["docker ps --format '{{.ID}}\\t{{.Names}}\\t{{.Status}}\\t{{.Image}}'"];
    assert_eq!(ps.exit_code, 0);

    let containers: Vec<&str> = ps.stdout.lines().collect();
    assert_eq!(containers.len(), 3, "Should have 3 containers");

    // Parse container names
    let names: Vec<&str> = containers
        .iter()
        .filter_map(|line| line.split('\t').nth(1))
        .collect();
    assert!(names.contains(&"web-app"));
    assert!(names.contains(&"api-server"));
    assert!(names.contains(&"redis-cache"));
}

#[test]
fn replay_docker_logs_contain_application_output() {
    let exchanges = load_fixture("docker_workflow.json");
    let responses = build_response_map(&exchanges);

    let logs = responses["docker logs --tail 20 web-app"];
    assert_eq!(logs.exit_code, 0);
    assert!(logs.stdout.contains("nginx"));
    // Should contain HTTP access log entries
    assert!(logs.stdout.contains("GET"));
}

#[test]
fn replay_docker_inspect_shows_running_state() {
    let exchanges = load_fixture("docker_workflow.json");
    let responses = build_response_map(&exchanges);

    let inspect =
        responses["docker inspect --format '{{.State.Status}} {{.State.StartedAt}}' web-app"];
    assert_eq!(inspect.exit_code, 0);
    assert!(inspect.stdout.starts_with("running"));
}

#[test]
fn replay_docker_stats_resource_usage() {
    let exchanges = load_fixture("docker_workflow.json");
    let responses = build_response_map(&exchanges);

    let stats =
        responses["docker stats --no-stream --format '{{.Name}}\\t{{.CPUPerc}}\\t{{.MemUsage}}'"];
    assert_eq!(stats.exit_code, 0);

    // Verify resource metrics are present
    assert!(stats.stdout.contains('%'), "CPU percentage expected");
    assert!(stats.stdout.contains("MiB"), "Memory usage expected");
}

// ─── Session workflow replay ───────────────────────────────────────

#[test]
fn replay_session_commands_in_order() {
    let exchanges = load_fixture("session_workflow.json");

    // Verify the workflow makes logical sense
    assert_eq!(exchanges[0].command, "echo ready");
    assert_eq!(exchanges[0].stdout.trim(), "ready");

    assert!(exchanges[1].command.contains("cd /var/log"));
    assert_eq!(exchanges[1].stdout.trim(), "/var/log");
}

#[test]
fn replay_session_log_analysis() {
    let exchanges = load_fixture("session_workflow.json");
    let responses = build_response_map(&exchanges);

    // Line count parsing
    let wc = responses["wc -l syslog"];
    assert_eq!(wc.exit_code, 0);
    let line_count: u64 = wc
        .stdout
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(line_count, 14523);

    // Tail shows recent entries
    let tail = responses["tail -3 syslog"];
    assert_eq!(tail.exit_code, 0);
    assert!(tail.stdout.contains("health-check"));
    assert!(tail.stdout.contains("all services healthy"));
}

#[test]
fn replay_session_all_commands_have_valid_exit_codes() {
    let exchanges = load_fixture("session_workflow.json");

    for exchange in &exchanges {
        assert_eq!(
            exchange.exit_code, 0,
            "Session workflow command '{}' should succeed",
            exchange.command
        );
    }
}

// ─── Fixture format validation ─────────────────────────────────────

#[test]
fn fixture_basic_commands_is_valid_json() {
    let exchanges = load_fixture("basic_commands.json");
    assert!(
        !exchanges.is_empty(),
        "basic_commands.json should have entries"
    );
    for exchange in &exchanges {
        assert!(!exchange.command.is_empty(), "command should not be empty");
        assert!(exchange.duration_ms > 0, "duration should be positive");
    }
}

#[test]
fn fixture_docker_workflow_is_valid_json() {
    let exchanges = load_fixture("docker_workflow.json");
    assert!(
        exchanges.len() >= 4,
        "docker_workflow.json should have at least 4 entries"
    );
}

#[test]
fn fixture_session_workflow_is_valid_json() {
    let exchanges = load_fixture("session_workflow.json");
    assert!(
        exchanges.len() >= 3,
        "session_workflow.json should have at least 3 entries"
    );
}

#[test]
fn all_fixtures_have_consistent_format() {
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let entries = std::fs::read_dir(&fixture_dir).expect("fixtures dir should exist");

    let mut fixture_count = 0;
    for entry in entries {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            fixture_count += 1;
            let content = std::fs::read_to_string(&path).unwrap();
            let exchanges: Vec<RecordedExchange> =
                serde_json::from_str(&content).unwrap_or_else(|e| {
                    panic!("Invalid fixture {}: {e}", path.display());
                });
            assert!(!exchanges.is_empty(), "Fixture {} is empty", path.display());
        }
    }

    assert!(
        fixture_count >= 3,
        "Expected at least 3 fixture files, found {fixture_count}"
    );
}

// ─── Cross-fixture consistency ─────────────────────────────────────

#[test]
fn no_fixture_has_negative_duration() {
    for fixture in &[
        "basic_commands.json",
        "docker_workflow.json",
        "session_workflow.json",
    ] {
        let exchanges = load_fixture(fixture);
        for exchange in &exchanges {
            // duration_ms is u64, so it can't be negative, but verify it's reasonable
            assert!(
                exchange.duration_ms < 60_000,
                "Duration > 60s in {fixture} for command '{}' seems unreasonable",
                exchange.command
            );
        }
    }
}

#[test]
fn no_fixture_has_duplicate_commands() {
    for fixture in &[
        "basic_commands.json",
        "docker_workflow.json",
        "session_workflow.json",
    ] {
        let exchanges = load_fixture(fixture);
        let mut seen = std::collections::HashSet::new();
        for exchange in &exchanges {
            assert!(
                seen.insert(&exchange.command),
                "Duplicate command '{}' in {fixture}",
                exchange.command
            );
        }
    }
}
