#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::certificate::CertificateCommandBuilder;

fuzz_target!(|data: &str| {
    // check
    let cmd = CertificateCommandBuilder::build_check_command(data, Some(443), Some(data));
    assert!(cmd.contains("openssl"), "check must contain 'openssl': {cmd}");

    // info
    let cmd = CertificateCommandBuilder::build_info_command(data);
    assert!(cmd.contains("openssl"), "info must contain 'openssl': {cmd}");

    // expiry (file mode)
    let cmd = CertificateCommandBuilder::build_expiry_command(data, true, Some(30));
    assert!(cmd.contains("openssl"), "expiry file must contain 'openssl': {cmd}");

    // expiry (host mode)
    let cmd = CertificateCommandBuilder::build_expiry_command(data, false, Some(7));
    assert!(cmd.contains("openssl"), "expiry host must contain 'openssl': {cmd}");
});
