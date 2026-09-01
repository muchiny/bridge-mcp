#![no_main]

use bridge_mcp::domain::use_cases::nginx::NginxCommandBuilder;
use bridge_mcp_fuzz::{assert_same_shell_skeleton, shell_shape};
use libfuzzer_sys::fuzz_target;

// These builders emit PIPELINES — `nginx -t 2>&1 && systemctl reload nginx`,
// `ls -la X 2>/dev/null || ... || echo 'none'` — so "the command contains no
// operators" is the wrong property: the operators are the builder's own and
// belong there. The right one is that the CALLER contributed none of them,
// which is what comparing the shell skeleton against a benign build says.
//
// `server` also selects among constants for the three names it knows, so a
// hostile value must not be able to reach the reload path of a known server.
fuzz_target!(|data: (&str, &str)| {
    let (server, config_dir) = data;

    for (name, hostile, benign) in [
        (
            "status",
            NginxCommandBuilder::build_status_command(Some(server)),
            NginxCommandBuilder::build_status_command(Some("nginx")),
        ),
        (
            "test",
            NginxCommandBuilder::build_test_command(Some(server)),
            NginxCommandBuilder::build_test_command(Some("zzz")),
        ),
        (
            "reload",
            NginxCommandBuilder::build_reload_command(Some(server)),
            NginxCommandBuilder::build_reload_command(Some("zzz")),
        ),
        (
            "list_sites",
            NginxCommandBuilder::build_list_sites_command(Some(server), Some(config_dir)),
            NginxCommandBuilder::build_list_sites_command(Some("nginx"), Some("/etc/x")),
        ),
    ] {
        // `test` and `reload` branch on the three server names they know, and
        // those branches emit different (constant) commands. Only compare
        // shapes when both sides took the unknown-server branch.
        if matches!(name, "test" | "reload")
            && matches!(server, "nginx" | "apache2" | "httpd")
        {
            // A known name selects a constant: assert it IS one.
            assert!(
                shell_shape(&hostile).is_some(),
                "{name}: a known server name must produce a scannable command: {hostile:?}"
            );
            continue;
        }
        assert_same_shell_skeleton(&benign, &hostile, name);
    }

    // Whatever the caller passed must arrive as text, not as a fragment of it.
    let sites =
        NginxCommandBuilder::build_list_sites_command(Some("nginx"), Some(config_dir));
    let shape = shell_shape(&sites)
        .unwrap_or_else(|| panic!("list_sites emitted an unscannable command: {sites:?}"));
    assert!(
        shape.literals.iter().any(|l| l == config_dir),
        "config_dir {config_dir:?} did not arrive intact; literals {:?} from {sites:?}",
        shape.literals
    );
});
