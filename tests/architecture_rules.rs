//! Architecture Enforcement Tests
//!
//! Verifies that the hexagonal architecture boundaries are respected:
//! - Domain layer must NOT import from adapters (ssh, mcp, config loader/watcher)
//! - Ports layer must NOT import from adapters (mcp)
//!
//! Known exceptions are documented and allowlisted to prevent new violations
//! while acknowledging existing intentional couplings.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Collect all `.rs` files under a directory recursively.
fn collect_rs_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if !dir.is_dir() {
        return files;
    }
    for entry in std::fs::read_dir(dir).expect("failed to read directory") {
        let entry = entry.expect("failed to read dir entry");
        let path = entry.path();
        if path.is_dir() {
            files.extend(collect_rs_files(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
    files
}

/// Extract all `use crate::` lines from a file, returning (line number, line content) pairs.
///
/// **This sees only `use` lines, so an INLINE path crosses every boundary
/// below unseen** — `crate::mcp::some_fn()` in the middle of an expression is
/// invisible here. That is not hypothetical: the audit-honesty wave moved
/// three types out of `src/mcp/` citing `domain_must_not_import_mcp_adapter`,
/// and the domain call the move exists to allow is itself an inline
/// `crate::security::…` path, so the rule was right and this test was green
/// for another reason.
///
/// **Measured, and deliberately NOT fixed here.** Widening the filter to
/// `trimmed.contains("crate::")` and the prefixes to bare paths was tried:
/// the four `domain_*` rules and `ports_must_not_import_cli` stay green — so
/// the wave's own justification holds under the stronger check — and exactly
/// one rule reddens, `ports_must_not_import_mcp_adapter`, on **14**
/// pre-existing inline `crate::mcp::protocol` / `crate::mcp::logger` /
/// `crate::mcp::progress` paths in `src/ports/tools.rs` (a file no commit of
/// that wave touched). Closing that is an architecture decision about
/// `ToolContext`, not a test fix, so it goes to the plan rather than being
/// smuggled in behind an allowlist entry.
fn extract_crate_imports(path: &Path) -> Vec<(usize, String)> {
    let content = std::fs::read_to_string(path).expect("failed to read file");
    content
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            let trimmed = line.trim();
            !trimmed.starts_with("//") && trimmed.starts_with("use crate::")
        })
        .map(|(num, line)| (num + 1, line.trim().to_string()))
        .collect()
}

/// An allowlisted exception to architecture rules.
struct Allowlisted {
    file_suffix: &'static str,
    import_fragment: &'static str,
}

/// Check for forbidden imports, excluding allowlisted exceptions.
fn check_forbidden_imports(
    files: &[PathBuf],
    forbidden_prefixes: &[&str],
    allowlist: &[Allowlisted],
) -> BTreeMap<String, Vec<(usize, String)>> {
    let mut violations = BTreeMap::new();

    for file in files {
        let imports = extract_crate_imports(file);
        let file_str = file.display().to_string();

        let file_violations: Vec<(usize, String)> = imports
            .into_iter()
            .filter(|(_, line)| {
                let is_forbidden = forbidden_prefixes
                    .iter()
                    .any(|prefix| line.contains(prefix));
                if !is_forbidden {
                    return false;
                }
                // Check if this violation is allowlisted
                let is_allowed = allowlist
                    .iter()
                    .any(|a| file_str.ends_with(a.file_suffix) && line.contains(a.import_fragment));
                !is_allowed
            })
            .collect();

        if !file_violations.is_empty() {
            let relative = file
                .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                .unwrap_or(file);
            violations.insert(relative.display().to_string(), file_violations);
        }
    }

    violations
}

fn format_violations(violations: &BTreeMap<String, Vec<(usize, String)>>) -> String {
    let mut msg = String::new();
    for (file, lines) in violations {
        for (line_num, line) in lines {
            use std::fmt::Write;
            let _ = writeln!(msg, "  {file}:{line_num}: {line}");
        }
    }
    msg
}

// ─── Domain layer rules ────────────────────────────────────────────

#[test]
fn domain_must_not_import_ssh_adapter() {
    let domain_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/domain");
    let files = collect_rs_files(&domain_dir);
    assert!(!files.is_empty(), "No domain source files found");

    let violations = check_forbidden_imports(&files, &["use crate::ssh::"], &[]);
    assert!(
        violations.is_empty(),
        "Domain layer must not import from SSH adapter:\n{}",
        format_violations(&violations)
    );
}

#[test]
fn domain_must_not_import_mcp_adapter() {
    let domain_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/domain");
    let files = collect_rs_files(&domain_dir);

    let violations = check_forbidden_imports(&files, &["use crate::mcp::"], &[]);
    assert!(
        violations.is_empty(),
        "Domain layer must not import from MCP adapter:\n{}",
        format_violations(&violations)
    );
}

#[test]
fn domain_must_not_import_config_loader() {
    let domain_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/domain");
    let files = collect_rs_files(&domain_dir);

    let violations = check_forbidden_imports(
        &files,
        &["use crate::config::loader", "use crate::config::watcher"],
        &[],
    );
    assert!(
        violations.is_empty(),
        "Domain layer must not import config loader/watcher (adapter-level):\n{}",
        format_violations(&violations)
    );
}

#[test]
fn domain_must_not_import_cli() {
    let domain_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/domain");
    let files = collect_rs_files(&domain_dir);

    let violations = check_forbidden_imports(&files, &["use crate::cli::"], &[]);
    assert!(
        violations.is_empty(),
        "Domain layer must not import from CLI adapter:\n{}",
        format_violations(&violations)
    );
}

#[test]
fn domain_security_import_limited_to_execute_command() {
    // execute_command.rs is the use case that orchestrates security checks.
    // No OTHER domain file should import security.
    let domain_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/domain");
    let files = collect_rs_files(&domain_dir);

    let allowlist = &[Allowlisted {
        file_suffix: "execute_command.rs",
        import_fragment: "crate::security::",
    }];

    let violations = check_forbidden_imports(&files, &["use crate::security::"], allowlist);
    assert!(
        violations.is_empty(),
        "Only execute_command.rs may import from security (use case orchestration):\n{}",
        format_violations(&violations)
    );
}

// ─── Ports layer rules ─────────────────────────────────────────────

#[test]
fn ports_must_not_import_mcp_adapter() {
    let ports_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ports");
    let files = collect_rs_files(&ports_dir);
    assert!(!files.is_empty(), "No ports source files found");

    let violations = check_forbidden_imports(&files, &["use crate::mcp::"], &[]);
    assert!(
        violations.is_empty(),
        "Ports layer must not import from MCP adapter:\n{}",
        format_violations(&violations)
    );
}

#[test]
fn ports_must_not_import_cli() {
    let ports_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ports");
    let files = collect_rs_files(&ports_dir);

    let violations = check_forbidden_imports(&files, &["use crate::cli::"], &[]);
    assert!(
        violations.is_empty(),
        "Ports layer must not import from CLI adapter:\n{}",
        format_violations(&violations)
    );
}

// ─── Sanity checks ─────────────────────────────────────────────────

#[test]
fn architecture_file_counts_sanity_check() {
    let domain_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/domain");
    let ports_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ports");

    let domain_files = collect_rs_files(&domain_dir);
    let ports_files = collect_rs_files(&ports_dir);

    // Domain should have 35+ files (use cases + supporting modules)
    assert!(
        domain_files.len() >= 35,
        "Expected at least 35 domain files, found {}. Directory structure may have changed.",
        domain_files.len()
    );

    // Ports should have at least 2 files
    assert!(
        ports_files.len() >= 2,
        "Expected at least 2 ports files, found {}. Directory structure may have changed.",
        ports_files.len()
    );
}
