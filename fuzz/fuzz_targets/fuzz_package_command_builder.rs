#![no_main]

use bridge_mcp::domain::use_cases::package::{
    PackageCommandBuilder, pkg_detect_prefix, validate_package_name, validate_search_query,
};
use bridge_mcp_fuzz::{assert_same_shell_skeleton, shell_shape};
use libfuzzer_sys::fuzz_target;

// The old target passed `Some("apt")` hard-coded and discarded every result,
// so it could not see the two things that mattered: that `pkg_manager` is
// accepted verbatim when it looks like a binary path, and that `filter` had no
// validator and landed in grep's OPTION position. Shell-escaping does not help
// there — `grep -i '-rf/etc/hostname'` is one shell word that getopt unbundles
// into `-r` plus `-f/etc/hostname`.
fuzz_target!(|data: (&str, &str)| {
    let (pkg_manager, value) = data;

    // ── the manager is either taken verbatim or replaced wholesale ────
    let prefix = pkg_detect_prefix(Some(pkg_manager));
    assert!(
        prefix == pkg_manager || prefix == pkg_detect_prefix(None),
        "pkg_manager {pkg_manager:?} produced neither itself nor the detection \
         script, but {prefix:?}"
    );

    // ── the caller adds no syntax, whichever manager is chosen ────────
    assert_same_shell_skeleton(
        &PackageCommandBuilder::build_search_command(Some("apt"), "nginx"),
        &PackageCommandBuilder::build_search_command(Some("apt"), value),
        "search query",
    );
    assert_same_shell_skeleton(
        &PackageCommandBuilder::build_install_command(Some("apt"), "nginx"),
        &PackageCommandBuilder::build_install_command(Some("apt"), value),
        "install package",
    );
    assert_same_shell_skeleton(
        &PackageCommandBuilder::build_remove_command(Some("apt"), "nginx"),
        &PackageCommandBuilder::build_remove_command(Some("apt"), value),
        "remove package",
    );

    // ── `--` stops the manager reading operands as options ────────────
    for (name, cmd) in [
        ("search", PackageCommandBuilder::build_search_command(Some("apt"), value)),
        ("install", PackageCommandBuilder::build_install_command(Some("apt"), value)),
        ("remove", PackageCommandBuilder::build_remove_command(Some("apt"), value)),
    ] {
        let shape = shell_shape(&cmd)
            .unwrap_or_else(|| panic!("{name}: emitted an unscannable command: {cmd:?}"));
        let Some(pos) = shape.literals.iter().position(|l| l == "--") else {
            panic!("{name}: no `--` before the operand, so {value:?} can be read as an option: {cmd:?}");
        };
        assert_eq!(
            shape.literals.get(pos + 1).map(String::as_str),
            Some(value),
            "{name}: the operand after `--` is not what was passed; \
             literals {:?} from {cmd:?}",
            shape.literals
        );
    }

    // ── the filter is a grep PATTERN, never a grep option ─────────────
    let filter_ok = validate_search_query(value).is_ok();
    let listed = PackageCommandBuilder::build_list_command(Some("apt"), Some(value));
    assert_eq!(
        listed.is_ok(),
        filter_ok,
        "list: builder disagrees with validate_search_query on filter {value:?}"
    );
    if let Ok(cmd) = listed {
        let shape = shell_shape(&cmd)
            .unwrap_or_else(|| panic!("list: emitted an unscannable command: {cmd:?}"));
        let Some(pos) = shape.literals.iter().position(|l| l == "-e") else {
            panic!("list: filter {value:?} was not passed as `-e PATTERN`, so grep reads it as an option: {cmd:?}");
        };
        assert_eq!(
            shape.literals.get(pos + 1).map(String::as_str),
            Some(value),
            "list: the word after `-e` is not the filter; literals {:?} from {cmd:?}",
            shape.literals
        );
    }

    // A name the validator accepted is a package, not an option.
    if validate_package_name(value).is_ok() {
        assert!(
            !value.starts_with('-'),
            "package name {value:?} was accepted but is an option to the manager"
        );
    }
});
