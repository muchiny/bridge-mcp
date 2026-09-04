//! Active Directory Command Builder
//!
//! Builds `PowerShell` Active Directory cmdlet commands for remote AD
//! management via SSH. Supports user listing, user info, group listing,
//! group membership, computer listing, and domain information retrieval.

use crate::config::ShellType;
use crate::domain::use_cases::shell::escape;
use crate::error::{BridgeError, Result};

/// Validates an Active Directory identity name to prevent command injection.
///
/// Identity names must be alphanumeric with hyphens, underscores, dots, and spaces.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the identity name is invalid.
pub fn validate_ad_identity(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "AD identity name cannot be empty".to_string(),
        });
    }
    if name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == ' ')
    {
        Ok(())
    } else {
        Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid AD identity name '{name}'. \
                 Only alphanumeric, hyphen, underscore, dot, and space allowed.",
            ),
        })
    }
}

/// Escape a value for safe interpolation into a `PowerShell` command.
fn ps_escape(s: &str) -> String {
    escape(s, ShellType::PowerShell)
}

/// Builds Active Directory `PowerShell` commands for remote execution.
pub struct ActiveDirectoryCommandBuilder;

impl ActiveDirectoryCommandBuilder {
    /// Build a `Get-ADUser` list command with optional filter.
    ///
    /// If `filter` is provided, constructs a `Name -like '*{filter}*'` filter.
    /// Otherwise, lists all users.
    ///
    /// The filter goes through [`validate_ad_identity`], like every other
    /// caller-supplied identity in this module, and is then interpolated RAW.
    ///
    /// It used to be interpolated as `ps_escape(f)` instead, and that was an
    /// injection rather than a defence. `ps_escape` produces a single-quoted
    /// PowerShell string, but this template drops it INSIDE A DOUBLE-QUOTED
    /// one — and PowerShell expands `$name` and `$(...)` inside double
    /// quotes. The single quotes were inert characters, so a filter of
    /// `$(Get-Content C:\secret)` was substituted by the remote shell before
    /// `Get-ADUser` ever saw it. `ps_escape` doubles quotes and touches
    /// neither `$` nor the backtick, because it is written for the
    /// single-quoted context its two sibling builders use
    /// (`-Identity {ps_escape(user)}`), where those characters are literal.
    ///
    /// The nesting was also wrong for benign input: the template already
    /// quotes the value (`'*{}*'`), so `bob` became `'*'bob'*'` — stray quotes
    /// inside the AD filter. Validating instead of escaping fixes both, and
    /// matches `ssh_ad_user_info` and `ssh_ad_group_members`, which already
    /// called `validate_ad_identity`. `ssh_ad_user_list` did not — the same
    /// one-place-missing-the-guard shape as the `Host *` defect in #177 — so
    /// the check lives HERE, in the one function that builds the command,
    /// rather than being added to the one handler that forgot it.
    ///
    /// Found by `fuzz_active_directory_builder`, on the input `$`.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the filter is not a valid AD
    /// identity.
    pub fn build_user_list_command(filter: Option<&str>) -> Result<String> {
        if let Some(f) = filter {
            validate_ad_identity(f)?;
            Ok(format!(
                "Get-ADUser -Filter \"Name -like '*{f}*'\" \
                 -Properties DisplayName,Enabled,LastLogonDate | \
                 Select-Object SamAccountName,DisplayName,Enabled,LastLogonDate | \
                 Sort-Object SamAccountName | Format-Table -AutoSize"
            ))
        } else {
            Ok("Get-ADUser -Filter * \
             -Properties DisplayName,Enabled,LastLogonDate | \
             Select-Object SamAccountName,DisplayName,Enabled,LastLogonDate | \
             Sort-Object SamAccountName | Format-Table -AutoSize"
                .to_string())
        }
    }

    /// Build a `Get-ADUser -Identity` command for detailed user info.
    ///
    /// Constructs: `Get-ADUser -Identity '{user}' -Properties * | Format-List`
    #[must_use]
    pub fn build_user_info_command(user: &str) -> String {
        format!(
            "Get-ADUser -Identity {} -Properties * | Format-List",
            ps_escape(user)
        )
    }

    /// Build a `Get-ADGroup` list command.
    ///
    /// Constructs: `Get-ADGroup -Filter * | Select-Object Name,GroupScope,GroupCategory
    /// | Sort-Object Name | Format-Table -AutoSize`
    #[must_use]
    pub fn build_group_list_command() -> String {
        "Get-ADGroup -Filter * | \
         Select-Object Name,GroupScope,GroupCategory | \
         Sort-Object Name | Format-Table -AutoSize"
            .to_string()
    }

    /// Build a `Get-ADGroupMember` command for a specific group.
    ///
    /// Constructs: `Get-ADGroupMember -Identity '{group}'
    /// | Select-Object Name,SamAccountName,objectClass
    /// | Sort-Object Name | Format-Table -AutoSize`
    #[must_use]
    pub fn build_group_members_command(group: &str) -> String {
        format!(
            "Get-ADGroupMember -Identity {} | \
             Select-Object Name,SamAccountName,objectClass | \
             Sort-Object Name | Format-Table -AutoSize",
            ps_escape(group)
        )
    }

    /// Build a `Get-ADComputer` list command.
    ///
    /// Constructs: `Get-ADComputer -Filter * -Properties OperatingSystem,LastLogonDate
    /// | Select-Object Name,OperatingSystem,LastLogonDate,Enabled
    /// | Sort-Object Name | Format-Table -AutoSize`
    #[must_use]
    pub fn build_computer_list_command() -> String {
        "Get-ADComputer -Filter * -Properties OperatingSystem,LastLogonDate | \
         Select-Object Name,OperatingSystem,LastLogonDate,Enabled | \
         Sort-Object Name | Format-Table -AutoSize"
            .to_string()
    }

    /// Build a domain and forest information command.
    ///
    /// Constructs: `Get-ADDomain | Format-List; Write-Output '---'; Get-ADForest | Format-List`
    #[must_use]
    pub fn build_domain_info_command() -> String {
        "Get-ADDomain | Format-List; Write-Output '---'; Get-ADForest | Format-List".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_ad_identity ─────────────────────────────────────────

    #[test]
    fn test_validate_ad_identity_valid() {
        assert!(validate_ad_identity("jdoe").is_ok());
        assert!(validate_ad_identity("John.Doe").is_ok());
        assert!(validate_ad_identity("my-user_name").is_ok());
        assert!(validate_ad_identity("Domain Admins").is_ok());
        assert!(validate_ad_identity("CN.User-Name_01").is_ok());
    }

    #[test]
    fn test_validate_ad_identity_empty() {
        assert!(validate_ad_identity("").is_err());
    }

    #[test]
    fn test_validate_ad_identity_injection() {
        assert!(validate_ad_identity("user; rm -rf /").is_err());
        assert!(validate_ad_identity("user && cat /etc/shadow").is_err());
        assert!(validate_ad_identity("user$(whoami)").is_err());
    }

    #[test]
    fn test_validate_ad_identity_pipe_rejected() {
        assert!(validate_ad_identity("user|bad").is_err());
    }

    #[test]
    fn test_validate_ad_identity_backtick_rejected() {
        assert!(validate_ad_identity("user`id`").is_err());
    }

    #[test]
    fn test_validate_ad_identity_dollar_rejected() {
        assert!(validate_ad_identity("user$PATH").is_err());
    }

    #[test]
    fn test_validate_ad_identity_single_quote_rejected() {
        assert!(validate_ad_identity("user'name").is_err());
    }

    #[test]
    fn test_validate_ad_identity_double_quote_rejected() {
        assert!(validate_ad_identity("user\"name").is_err());
    }

    #[test]
    fn test_validate_ad_identity_error_message() {
        let result = validate_ad_identity("bad;name");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("bad;name"));
            }
            other => panic!("Expected BridgeError::CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_ad_identity_error_message_empty() {
        let result = validate_ad_identity("");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("cannot be empty"));
            }
            other => panic!("Expected BridgeError::CommandDenied, got: {other:?}"),
        }
    }

    // ── build_user_list_command ───────────────────────────────────────

    #[test]
    fn test_user_list_no_filter() {
        let cmd = ActiveDirectoryCommandBuilder::build_user_list_command(None).unwrap();
        assert!(cmd.starts_with("Get-ADUser -Filter *"));
        assert!(cmd.contains("DisplayName,Enabled,LastLogonDate"));
        assert!(cmd.contains("Select-Object SamAccountName,DisplayName,Enabled,LastLogonDate"));
        assert!(cmd.contains("Sort-Object SamAccountName"));
        assert!(cmd.contains("Format-Table -AutoSize"));
    }

    #[test]
    fn test_user_list_with_filter() {
        let cmd = ActiveDirectoryCommandBuilder::build_user_list_command(Some("john")).unwrap();
        // No stray quotes. This used to assert `Name -like '*'john'*'` --
        // the template already quotes the value and `ps_escape` added a
        // second pair, so the AD filter carried quotes nobody meant to
        // send. The test encoded the defect as the expectation.
        assert!(cmd.contains("Name -like '*john*'"), "{cmd}");
        assert!(cmd.contains("DisplayName,Enabled,LastLogonDate"));
        assert!(cmd.contains("Sort-Object SamAccountName"));
        assert!(cmd.contains("Format-Table -AutoSize"));
    }

    #[test]
    fn test_user_list_filter_with_special_chars() {
        // Was: "PowerShell escaping doubles single quotes", asserting
        // `'it''s'` came through. Doubling is the correct escape for a
        // SINGLE-quoted context; this template is double-quoted, where
        // those quotes are inert characters. A quote is refused now.
        assert!(ActiveDirectoryCommandBuilder::build_user_list_command(Some("it's")).is_err());
    }

    /// The input `fuzz_active_directory_builder` failed on, and the reason
    /// the builder changed: inside PowerShell DOUBLE quotes, `$` is live.
    /// `ps_escape` doubles quotes and touches neither `$` nor the backtick,
    /// so the filter reached the remote shell as an expression to evaluate.
    #[test]
    fn test_user_list_filter_refuses_powershell_expansion() {
        for hostile in [
            "$",
            "$(Get-Content C:\\secret)",
            "$env:USERNAME",
            "`n",
            "a\"b",
        ] {
            assert!(
                ActiveDirectoryCommandBuilder::build_user_list_command(Some(hostile)).is_err(),
                "filter {hostile:?} must be refused: it lands inside a \
                 double-quoted PowerShell string, where the shell expands it"
            );
        }
    }

    // ── build_user_info_command ──────────────────────────────────────

    #[test]
    fn test_user_info_command() {
        let cmd = ActiveDirectoryCommandBuilder::build_user_info_command("jdoe");
        assert_eq!(
            cmd,
            "Get-ADUser -Identity 'jdoe' -Properties * | Format-List"
        );
    }

    #[test]
    fn test_user_info_command_with_special_chars() {
        let cmd = ActiveDirectoryCommandBuilder::build_user_info_command("j.doe");
        assert_eq!(
            cmd,
            "Get-ADUser -Identity 'j.doe' -Properties * | Format-List"
        );
    }

    #[test]
    fn test_user_info_injection_escaped() {
        let cmd = ActiveDirectoryCommandBuilder::build_user_info_command("user'; Remove-Item -r /");
        // PowerShell escaping doubles the single quote
        assert!(cmd.contains("'user''; Remove-Item -r /'"));
    }

    // ── build_group_list_command ─────────────────────────────────────

    #[test]
    fn test_group_list_command() {
        let cmd = ActiveDirectoryCommandBuilder::build_group_list_command();
        assert!(cmd.starts_with("Get-ADGroup -Filter *"));
        assert!(cmd.contains("Name,GroupScope,GroupCategory"));
        assert!(cmd.contains("Sort-Object Name"));
        assert!(cmd.contains("Format-Table -AutoSize"));
    }

    // ── build_group_members_command ──────────────────────────────────

    #[test]
    fn test_group_members_command() {
        let cmd = ActiveDirectoryCommandBuilder::build_group_members_command("Domain Admins");
        assert!(cmd.contains("Get-ADGroupMember -Identity 'Domain Admins'"));
        assert!(cmd.contains("Name,SamAccountName,objectClass"));
        assert!(cmd.contains("Sort-Object Name"));
        assert!(cmd.contains("Format-Table -AutoSize"));
    }

    #[test]
    fn test_group_members_injection_escaped() {
        let cmd =
            ActiveDirectoryCommandBuilder::build_group_members_command("group'; Remove-Item -r /");
        assert!(cmd.contains("'group''; Remove-Item -r /'"));
    }

    // ── build_computer_list_command ──────────────────────────────────

    #[test]
    fn test_computer_list_command() {
        let cmd = ActiveDirectoryCommandBuilder::build_computer_list_command();
        assert!(cmd.starts_with("Get-ADComputer -Filter *"));
        assert!(cmd.contains("OperatingSystem,LastLogonDate"));
        assert!(cmd.contains("Name,OperatingSystem,LastLogonDate,Enabled"));
        assert!(cmd.contains("Sort-Object Name"));
        assert!(cmd.contains("Format-Table -AutoSize"));
    }

    // ── build_domain_info_command ────────────────────────────────────

    #[test]
    fn test_domain_info_command() {
        let cmd = ActiveDirectoryCommandBuilder::build_domain_info_command();
        assert_eq!(
            cmd,
            "Get-ADDomain | Format-List; Write-Output '---'; Get-ADForest | Format-List"
        );
    }

    // ── Shell Injection Prevention ───────────────────────────────────

    #[test]
    fn test_user_info_semicolon_injection() {
        let cmd = ActiveDirectoryCommandBuilder::build_user_info_command("user; whoami");
        // The semicolon is safely inside single quotes
        assert!(cmd.contains("'user; whoami'"));
    }

    #[test]
    fn test_group_members_dollar_injection() {
        let cmd = ActiveDirectoryCommandBuilder::build_group_members_command("group$(hostname)");
        // Dollar sign is safely inside single quotes (PowerShell does not expand in single quotes)
        assert!(cmd.contains("'group$(hostname)'"));
    }

    #[test]
    fn test_user_list_filter_injection() {
        // Was: assert the quotes came back doubled, as though that were
        // the defence. It was not -- see `build_user_list_command`.
        assert!(
            ActiveDirectoryCommandBuilder::build_user_list_command(Some("'; Remove-Item *; '"))
                .is_err()
        );
    }

    // ── Edge Cases ───────────────────────────────────────────────────

    #[test]
    fn test_validate_ad_identity_spaces_only() {
        // Spaces are allowed characters, so a space-only name is valid syntactically
        assert!(validate_ad_identity("   ").is_ok());
    }

    #[test]
    fn test_validate_ad_identity_long_name() {
        let long_name = "a".repeat(256);
        assert!(validate_ad_identity(&long_name).is_ok());
    }

    #[test]
    fn test_validate_ad_identity_unicode_rejected() {
        assert!(validate_ad_identity("user\u{00e9}").is_err());
    }

    #[test]
    fn test_validate_ad_identity_newline_rejected() {
        assert!(validate_ad_identity("user\nname").is_err());
    }

    #[test]
    fn test_validate_ad_identity_tab_rejected() {
        assert!(validate_ad_identity("user\tname").is_err());
    }

    #[test]
    fn test_user_info_empty_string() {
        let cmd = ActiveDirectoryCommandBuilder::build_user_info_command("");
        assert_eq!(cmd, "Get-ADUser -Identity '' -Properties * | Format-List");
    }

    #[test]
    fn test_group_members_empty_string() {
        let cmd = ActiveDirectoryCommandBuilder::build_group_members_command("");
        assert!(cmd.contains("Get-ADGroupMember -Identity ''"));
    }

    #[test]
    fn test_user_list_empty_filter() {
        // `validate_ad_identity` refuses an empty identity, and an empty
        // filter means `Name -like '**'` -- every user, which the `None`
        // branch already says honestly.
        assert!(ActiveDirectoryCommandBuilder::build_user_list_command(Some("")).is_err());
    }
}
