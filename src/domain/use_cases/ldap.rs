//! LDAP Command Builder
//!
//! Builds ldapsearch, ldapadd, and ldapmodify commands for `OpenLDAP` operations.

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Escape a value for safe inclusion inside an LDAP filter (RFC 4515 §3).
///
/// Encodes the four filter metacharacters `( ) * \` plus NUL.
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

/// Whether `token` is an attribute selector `ldapsearch` accepts: `*`, `+`,
/// or a name (optionally `@`-prefixed object class) of letters, digits, `.`,
/// `;`, `-` and `_` that starts with a letter or digit.
fn is_attribute_name(token: &str) -> bool {
    if token == "*" || token == "+" {
        return true;
    }
    let name = token.strip_prefix('@').unwrap_or(token);
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ';' | '-' | '_'))
}

/// Builds LDAP CLI commands for remote execution.
pub struct LdapCommandBuilder;

impl LdapCommandBuilder {
    /// Build an ldapsearch command.
    #[must_use]
    pub fn build_search_command(
        base_dn: &str,
        filter: Option<&str>,
        attributes: Option<&str>,
        scope: Option<&str>,
        uri: Option<&str>,
    ) -> String {
        let mut cmd = String::from("ldapsearch -x -LLL");
        if let Some(u) = uri {
            let _ = write!(cmd, " -H {}", shell_escape(u));
        }
        let _ = write!(cmd, " -b {}", shell_escape(base_dn));
        if let Some(s) = scope {
            let _ = write!(cmd, " -s {}", shell_escape(s));
        }
        // `ldapsearch [options] [filter [attributes...]]`: the first operand is
        // always the filter, so a filter stands in when only attributes are
        // given, and `--` keeps an operand that starts with `-` from being
        // read as an option.
        if filter.is_some() || attributes.is_some() {
            cmd.push_str(" --");
            let _ = write!(
                cmd,
                " {}",
                shell_escape(filter.unwrap_or("(objectClass=*)"))
            );
        }
        for attribute in attributes.unwrap_or_default().split_whitespace() {
            let _ = write!(cmd, " {}", shell_escape(attribute));
        }
        cmd
    }

    /// Build an ldapsearch for a specific user.
    #[must_use]
    pub fn build_user_info_command(base_dn: &str, username: &str, uri: Option<&str>) -> String {
        let filter = format!("(uid={})", ldap_filter_escape(username));
        Self::build_search_command(base_dn, Some(&filter), None, Some("sub"), uri)
    }

    /// Build an ldapsearch for group members.
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

    /// Build an ldapadd command (from LDIF on stdin).
    #[must_use]
    pub fn build_add_command(ldif_content: &str, uri: Option<&str>) -> String {
        let mut cmd = String::from("ldapadd -x");
        if let Some(u) = uri {
            let _ = write!(cmd, " -H {}", shell_escape(u));
        }
        let escaped = shell_escape(ldif_content);
        format!("printf '%s' {escaped} | {cmd}")
    }

    /// Build an ldapmodify command (from LDIF on stdin).
    #[must_use]
    pub fn build_modify_command(ldif_content: &str, uri: Option<&str>) -> String {
        let mut cmd = String::from("ldapmodify -x");
        if let Some(u) = uri {
            let _ = write!(cmd, " -H {}", shell_escape(u));
        }
        let escaped = shell_escape(ldif_content);
        format!("printf '%s' {escaped} | {cmd}")
    }

    /// Validate the `attributes` of an ldapsearch: whitespace-separated
    /// attribute names (`cn`, `userCertificate;binary`, `@person`, `*`, `+`,
    /// `1.1`), nothing else.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` naming `attributes`.
    pub fn validate_attributes(attributes: &str) -> Result<()> {
        if attributes.split_whitespace().all(is_attribute_name) {
            Ok(())
        } else {
            Err(BridgeError::CommandDenied {
                reason: "'attributes' must be space-separated attribute names \
                         (letters, digits, '.', ';', '-', '_', or '*', '+')"
                    .to_string(),
            })
        }
    }

    /// Refuse LDIF that makes `ldapadd`/`ldapmodify` read a local file.
    ///
    /// The client reads a file on the host it runs on, and sends it to the
    /// server, in three ways, all refused here:
    /// - an `attr:< file:///path` line (the value starts with `<`);
    /// - a `control` line in any form (`control:`, `control::`), whose
    ///   optional control value is parsed like an attribute value, after
    ///   base64 decoding for `control::`, so a `:<` in it makes the client
    ///   read a file. Controls are refused outright rather than decoded;
    /// - an `include: <url>` line, which splices in another file whose own
    ///   `attr:<` lines this check never sees.
    ///
    /// A carriage return that does not end a line (`\r\n`) is refused as
    /// well: the client drops a lone `\r` from a value, so text split by one
    /// (`false:\r< file:///...`) reads differently to the client than to this
    /// check. CRLF line ends are read as `\n`, as the client reads them.
    ///
    /// Line types are matched case-insensitively, like the client does.
    /// Continuation lines (a leading space) are joined before the check.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` naming `ldif`.
    pub fn validate_ldif(ldif: &str) -> Result<()> {
        let ldif = ldif.replace("\r\n", "\n");
        if ldif.contains('\r') {
            return Err(BridgeError::CommandDenied {
                reason: "'ldif' must not contain a carriage return outside a CRLF line end"
                    .to_string(),
            });
        }
        let mut logical: Vec<String> = Vec::new();
        for line in ldif.split('\n') {
            match (line.strip_prefix(' '), logical.last_mut()) {
                (Some(rest), Some(previous)) => previous.push_str(rest),
                _ => logical.push(line.to_string()),
            }
        }
        let reads_a_file = logical
            .iter()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split_once(':'))
            .any(|(line_type, value)| {
                let line_type = line_type.trim();
                value.starts_with('<')
                    || line_type.eq_ignore_ascii_case("include")
                    || line_type.eq_ignore_ascii_case("control")
            });
        if reads_a_file {
            return Err(BridgeError::CommandDenied {
                reason: "'ldif' must not read a value from a file ('attr:< file:///...'), \
                         carry a 'control:' line (its value can read a file) nor include \
                         another file ('include:'): the client would read it on the remote host"
                    .to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_simple() {
        let cmd =
            LdapCommandBuilder::build_search_command("dc=example,dc=com", None, None, None, None);
        assert!(cmd.contains("ldapsearch"));
        assert!(cmd.contains("-b"));
    }

    #[test]
    fn test_search_with_filter() {
        let cmd = LdapCommandBuilder::build_search_command(
            "dc=example,dc=com",
            Some("(objectClass=person)"),
            Some("cn mail"),
            Some("sub"),
            Some("ldap://ldap.example.com"),
        );
        assert!(cmd.contains("-H"));
        assert!(cmd.contains("-s"));
        assert!(cmd.contains("-- '(objectClass=person)' 'cn' 'mail'"));
    }

    #[test]
    fn test_user_info() {
        let cmd = LdapCommandBuilder::build_user_info_command("dc=example,dc=com", "jdoe", None);
        assert!(cmd.contains("uid=jdoe"));
    }

    #[test]
    fn test_group_members() {
        let cmd = LdapCommandBuilder::build_group_members_command(
            "dc=example,dc=com",
            "developers",
            None,
        );
        assert!(cmd.contains("cn=developers"));
        assert!(cmd.contains("'member' 'memberUid'"));
    }

    #[test]
    fn test_add() {
        let cmd = LdapCommandBuilder::build_add_command("dn: cn=test\nobjectClass: top", None);
        assert!(cmd.contains("ldapadd"));
        assert!(cmd.contains("printf '%s' 'dn: cn=test\nobjectClass: top'"));
    }

    #[test]
    fn test_modify() {
        let cmd = LdapCommandBuilder::build_modify_command(
            "dn: cn=test\nchangetype: modify",
            Some("ldap://localhost"),
        );
        assert!(cmd.contains("ldapmodify"));
        assert!(cmd.contains("-H"));
    }

    #[test]
    fn test_user_info_escapes_filter_metacharacters() {
        let cmd =
            LdapCommandBuilder::build_user_info_command("dc=example,dc=com", "*)(uid=*", None);
        assert!(
            !cmd.contains("(uid=*)(uid=*"),
            "raw injection must not appear"
        );
        assert!(cmd.contains(r"\2a"), "asterisk must be RFC 4515 encoded");
        assert!(
            cmd.contains(r"\28") || cmd.contains(r"\29"),
            "parens must be encoded"
        );
    }

    #[test]
    fn test_group_members_escapes_filter_metacharacters() {
        let cmd = LdapCommandBuilder::build_group_members_command(
            "dc=example,dc=com",
            "admins)(member=*",
            None,
        );
        assert!(!cmd.contains("(cn=admins)(member="));
        assert!(cmd.contains(r"\29"));
    }

    #[test]
    fn test_user_info_passthrough_clean_value() {
        let cmd = LdapCommandBuilder::build_user_info_command("dc=example,dc=com", "alice", None);
        // The filter string can be quoted by shell_escape, so accept either form.
        assert!(cmd.contains("(uid=alice)") || cmd.contains("'(uid=alice)'"));
    }

    #[test]
    fn test_group_members_passthrough_clean_value() {
        let cmd =
            LdapCommandBuilder::build_group_members_command("dc=example,dc=com", "admins", None);
        assert!(cmd.contains("(cn=admins)") || cmd.contains("'(cn=admins)'"));
    }

    #[test]
    fn test_search_attributes_are_one_quoted_word_each() {
        let cmd = LdapCommandBuilder::build_search_command(
            "dc=x",
            Some("(cn=a)"),
            Some("cn  mail\tuserCertificate;binary"),
            None,
            None,
        );
        assert!(cmd.ends_with("-- '(cn=a)' 'cn' 'mail' 'userCertificate;binary'"));
    }

    #[test]
    fn test_search_attributes_without_filter_get_a_default_filter() {
        let cmd = LdapCommandBuilder::build_search_command("dc=x", None, Some("cn"), None, None);
        assert!(cmd.ends_with("-- '(objectClass=*)' 'cn'"));
    }

    #[test]
    fn test_search_dashed_filter_follows_double_dash() {
        let cmd = LdapCommandBuilder::build_search_command("dc=x", Some("-W"), None, None, None);
        assert!(cmd.ends_with("-- '-W'"));
    }

    #[test]
    fn test_validate_attributes_refuses_shell_text() {
        for bad in ["cn; id #", "cn $(id)", "-W", "cn`id`", "a|b", "'x'"] {
            match LdapCommandBuilder::validate_attributes(bad) {
                Err(BridgeError::CommandDenied { reason }) => {
                    assert!(reason.contains("'attributes'"), "{bad}");
                }
                other => panic!("expected CommandDenied for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_validate_attributes_accepts_names() {
        for good in [
            "cn mail",
            "*",
            "+",
            "1.1",
            "@person",
            "userCertificate;binary",
            "sn  givenName",
        ] {
            assert!(
                LdapCommandBuilder::validate_attributes(good).is_ok(),
                "{good}"
            );
        }
    }

    #[test]
    fn test_add_ldif_is_never_a_printf_format() {
        let cmd = LdapCommandBuilder::build_add_command("-ZQX %s %n \\n", None);
        assert!(cmd.starts_with("printf '%s' '-ZQX %s %n \\n' | ldapadd"));
        let cmd = LdapCommandBuilder::build_modify_command("---\n- item", None);
        assert!(cmd.starts_with("printf '%s' '---\n- item' | ldapmodify"));
    }

    #[test]
    fn test_validate_ldif_refuses_file_values() {
        for bad in [
            "dn: cn=x,dc=e\nsn:< file:///etc/shadow",
            "dn: cn=x,dc=e\njpegPhoto:<file:///etc/passwd\n",
            "dn: cn=x,dc=e\nsn:\n < file:///etc/shadow",
            // The optional value of a control is parsed like an attribute value.
            "dn: cn=x,dc=e\ncontrol: 1.2.3.4 false:< file:///home/bridge/.ssh/id_ed25519\ncn: x",
            "dn: cn=x,dc=e\nControl: 1.2.3.4 true:< file:///x",
            "dn: cn=x,dc=e\nCONTROL: 1.2.3.4:< file:///x",
            "dn: cn=x,dc=e\ncontrol: 1.2.3.4 false:\n < file:///x",
            "dn: cn=x,dc=e\ncontrol: 1.2.3.4 false\n :< file:///x",
            // Base64 form: decoded by the client, then parsed like a value.
            "dn: cn=x,dc=example,dc=com\ncontrol:: MS4yLjMuNCBmYWxzZTo8IGZpbGU6Ly8vaG9tZS9icmlkZ2UvLnNzaC9pZF9lZDI1NTE5\nobjectClass: top\ncn: x",
            "dn: cn=x,dc=e\nCONTROL:: MS4yLjMuNA==",
            "dn: cn=x,dc=e\ncontrol : 1.2.3.4",
            "dn: cn=x,dc=e\ncon\n trol:: MS4yLjMuNA==",
            // Plain control without a file value: refused too.
            "dn: cn=x,dc=e\ncontrol: 1.2.3.4 false",
            // `include:` splices in another file whose lines are never checked.
            "include: file:///tmp/staged.ldif",
            "dn: cn=x,dc=e\nINCLUDE: file:///tmp/a.ldif",
            "dn: cn=x,dc=e\ninclude:file:///tmp/a.ldif",
            "dn: cn=x,dc=e\ninc\n lude: file:///tmp/a.ldif",
        ] {
            match LdapCommandBuilder::validate_ldif(bad) {
                Err(BridgeError::CommandDenied { reason }) => {
                    assert!(reason.contains("'ldif'"), "{bad}");
                }
                other => panic!("expected CommandDenied for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_validate_ldif_refuses_carriage_returns() {
        for bad in [
            // The client drops the lone CR and reads `false:< file:///...`.
            "dn: cn=x,dc=e\ncontrol: 1.2.3.4 false:\r< file:///home/bridge/.ssh/id_ed25519\ncn: x",
            "dn: cn=x,dc=e\r\ndescription: a\r\r\ncn: x\r\n",
            "dn: cn=x,dc=e\rcn: x",
            "dn: cn=x,dc=e\ndescription: a\r",
        ] {
            match LdapCommandBuilder::validate_ldif(bad) {
                Err(BridgeError::CommandDenied { reason }) => {
                    assert!(reason.contains("'ldif'"), "{bad}");
                }
                other => panic!("expected CommandDenied for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_validate_ldif_accepts_crlf_and_still_sees_through_it() {
        assert!(LdapCommandBuilder::validate_ldif("dn: cn=x,dc=e\r\ncn: x\r\n").is_ok());
        assert!(
            LdapCommandBuilder::validate_ldif(
                "dn: cn=x,dc=e\r\njpegPhoto:< file:///etc/shadow\r\n"
            )
            .is_err()
        );
        assert!(
            LdapCommandBuilder::validate_ldif(
                "dn: cn=x,dc=e\r\ndescription: a\r\n < file:///x\r\n"
            )
            .is_ok(),
            "a continued value that merely contains '<' reads no file"
        );
    }

    #[test]
    fn test_validate_ldif_accepts_ordinary_entries() {
        let ldif = "dn: cn=x,dc=e\nobjectClass: person\ncn: x\n# note a:<b\nsn: a<b\n\
                    description: a:<b\nuserPassword:: PGZpbGU6Ly8+\n";
        assert!(LdapCommandBuilder::validate_ldif(ldif).is_ok());
        // Values that merely mention the words.
        let ldif = "dn: cn=x,dc=e\ncontrolled: 1.2.3.4 false\n\
                    description: include: foo\ndescription: control: 1:<x\n\
                    # include: file:///x\n# control: 1 true:< file:///x\ncn: includes\n";
        assert!(LdapCommandBuilder::validate_ldif(ldif).is_ok());
    }
}
