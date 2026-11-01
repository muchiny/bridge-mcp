//! Parse-only check of PowerShell quoting against the real PowerShell parser.
//!
//! `Parser::ParseInput` builds an AST and executes nothing. The test is
//! skipped when `pwsh` is not on `PATH`.

use bridge_mcp::config::ShellType;
use bridge_mcp::domain::use_cases::shell::escape;

const PARSE: &str = "$t=$null;$e=$null;$a=[System.Management.Automation.Language.Parser]::ParseInput($env:BMCP_PS_INPUT,[ref]$t,[ref]$e);$el=$a.EndBlock.Statements[0].PipelineElements[0].CommandElements;'errors={0} statements={1} elements={2} value={3}' -f $e.Count,$a.EndBlock.Statements.Count,$el.Count,(($el[1].Value.ToCharArray()|ForEach-Object{'{0:X4}' -f [int]$_}) -join ',')";

/// First `PATH` entry joined with `pwsh` that is a file.
fn pwsh_on_path() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("pwsh"))
        .find(|candidate| candidate.is_file())
}

/// UTF-16 code units in upper-case hex, comma separated: what
/// `String.ToCharArray()` yields on the PowerShell side.
fn hex(s: &str) -> String {
    s.encode_utf16()
        .map(|unit| format!("{unit:04X}"))
        .collect::<Vec<_>>()
        .join(",")
}

#[test]
fn escaped_values_parse_as_one_literal_in_pwsh() {
    let Some(pwsh) = pwsh_on_path() else {
        eprintln!("pwsh not on PATH: skipped");
        return;
    };
    for input in [
        "plain",
        "it's",
        "a\u{2019}b",
        "x'\u{2019}\u{2018}\u{201A}\u{201B}'y",
        "\u{2019}",
        "a\u{2019}; Write-Output pwned; \u{2019}",
        "$(Write-Output pwned)",
        "a\u{201C}b\u{201D}",
        "",
        "a'",
        "\u{201B}\u{201B}\u{201B}",
        "\u{2018}",
        "\u{201A}",
        "\u{201B}",
        "a`b",
        "a\nb",
        "\u{1F600}",
        "\u{1F600}\u{2019}",
    ] {
        let script = format!("Write-Output {}", escape(input, ShellType::PowerShell));
        let out = std::process::Command::new(&pwsh)
            .args(["-NoProfile", "-NonInteractive", "-Command", PARSE])
            .env("BMCP_PS_INPUT", &script)
            .output()
            .expect("pwsh runs");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim_end(),
            format!("errors=0 statements=1 elements=2 value={}", hex(input)),
            "input {input:?}, script {script:?}"
        );
    }
}
