#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::redis::RedisCommandBuilder;

fuzz_target!(|data: &str| {
    // validate_redis_command
    let _ = RedisCommandBuilder::validate_redis_command(data);

    // info
    let cmd = RedisCommandBuilder::build_info_command(Some(data), Some(6379), Some(data));
    assert!(cmd.contains("redis-cli"), "info must contain 'redis-cli': {cmd}");

    // cli
    let cmd = RedisCommandBuilder::build_cli_command(Some(data), Some(6379), data);
    assert!(cmd.contains("redis-cli"), "cli must contain 'redis-cli': {cmd}");

    // keys
    let cmd = RedisCommandBuilder::build_keys_command(Some(data), Some(6379), Some(data), Some(100));
    assert!(cmd.contains("redis-cli"), "keys must contain 'redis-cli': {cmd}");
});
