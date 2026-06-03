#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::package::{
    validate_package_name, validate_search_query, PackageCommandBuilder,
};

fuzz_target!(|data: &str| {
    // validators
    let _ = validate_package_name(data);
    let _ = validate_search_query(data);

    // list
    let _ = PackageCommandBuilder::build_list_command(Some("apt"), Some(data));

    // search
    let _ = PackageCommandBuilder::build_search_command(Some("apt"), data);

    // install
    let _ = PackageCommandBuilder::build_install_command(Some("apt"), data);

    // remove
    let _ = PackageCommandBuilder::build_remove_command(Some("apt"), data);

    // update
    let _ = PackageCommandBuilder::build_update_command(Some("apt"), Some(data));
});
