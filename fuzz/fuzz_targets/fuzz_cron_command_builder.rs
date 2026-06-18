#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::cron::{
    validate_cron_comment, validate_cron_schedule, CronCommandBuilder,
};

fuzz_target!(|data: &str| {
    // validators
    let _ = validate_cron_schedule(data);
    let _ = validate_cron_comment(data);

    // list
    let cmd = CronCommandBuilder::build_list_command(Some(data), true);
    assert!(cmd.contains("crontab"), "list must contain 'crontab': {cmd}");

    // add (may fail validation)
    let _ = CronCommandBuilder::build_add_command(data, data, Some(data), Some(data));

    // remove
    let _ = CronCommandBuilder::build_remove_command(data, Some(data));
});
