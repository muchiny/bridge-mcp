#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::terraform::{
    validate_terraform_dir, TerraformCommandBuilder,
};

fuzz_target!(|data: &str| {
    let vars = vec![data.to_string()];
    let targets = vec![data.to_string()];

    // validate_terraform_dir
    let _ = validate_terraform_dir(data);

    // init
    if let Ok(cmd) = TerraformCommandBuilder::build_init_command(data, true, true) {
        assert!(cmd.contains("terraform"), "init must contain 'terraform': {cmd}");
    }

    // plan
    if let Ok(cmd) = TerraformCommandBuilder::build_plan_command(
        data,
        Some(&vars),
        Some(data),
        Some(&targets),
        Some(data),
        true,
    ) {
        assert!(cmd.contains("terraform"), "plan must contain 'terraform': {cmd}");
    }

    // apply
    if let Ok(cmd) = TerraformCommandBuilder::build_apply_command(
        data,
        true,
        Some(&vars),
        Some(data),
        Some(&targets),
        Some(data),
    ) {
        assert!(cmd.contains("terraform"), "apply must contain 'terraform': {cmd}");
    }

    // validate_state_subcommand
    let _ = TerraformCommandBuilder::validate_state_subcommand(data);

    // state
    if let Ok(cmd) = TerraformCommandBuilder::build_state_command(data, "list", Some(data)) {
        assert!(cmd.contains("terraform"), "state must contain 'terraform': {cmd}");
    }

    // output
    if let Ok(cmd) = TerraformCommandBuilder::build_output_command(data, Some(data), true) {
        assert!(cmd.contains("terraform"), "output must contain 'terraform': {cmd}");
    }
});
