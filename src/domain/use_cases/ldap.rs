//! LDAP Command Builder
//!
//! Builds ldapsearch, ldapadd, and ldapmodify commands for `OpenLDAP` operations.
//!
//! Every command is a simple bind (`-x`): the tools send no bind DN and no
//! password, so the bind is anonymous and no `SASL` mechanism (`EXTERNAL`,
//! `GSSAPI`) is used. The one credential a client of the host can still
//! present is the TLS client certificate that `TLS_CERT` / `TLS_KEY` of the
//! user's `ldaprc` (or `LDAPTLS_CERT` / `LDAPTLS_KEY`) name: it goes out in
//! the handshake with an `ldaps://` server. For any server but the host's own
//! the call therefore runs with `LDAPTLS_CERT` and `LDAPTLS_KEY` set empty.

use std::fmt::Write;
use std::net::Ipv6Addr;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

use super::shell::is_loopback_host;

/// Longest `uri` accepted.
const LDAP_URI_MAX_LEN: usize = 255;

/// Environment of an LDAP client that connects to another server than the
/// host's own: an empty `LDAPTLS_CERT` and `LDAPTLS_KEY` take precedence over
/// `TLS_CERT` and `TLS_KEY` of every `ldaprc` (environment variables are the
/// last source `libldap` reads), so the client certificate stored on the host
/// is not presented in the TLS handshake. `TLS_CACERT` and `TLS_REQCERT` stay
/// as configured: they decide whom the client trusts, not who it is. The tools
/// use a simple bind without a bind DN, so `BINDDN` and `SASL_*` options do not
/// apply (the client ignores `BINDDN` from `ldaprc`).
const LDAP_REMOTE_ENV: &str = "LDAPTLS_CERT= LDAPTLS_KEY= ";

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

/// What the `scheme://authority` part of a `uri` designates.
#[derive(Debug, PartialEq, Eq)]
enum LdapTarget<'a> {
    /// `ldapi://`: a `UNIX` socket of the host itself.
    Socket,
    /// `ldap://` or `ldaps://`: a host name or an IP address (without the
    /// brackets of an `IPv6` address).
    Network(&'a str),
}

/// Split a `uri` into what it designates, or `None` when it is not exactly
/// one `ldap://`, `ldaps://` or `ldapi://` URI of the form `scheme://authority`
/// (one optional trailing `/`).
///
/// - `ldap`, `ldaps`: a host (ASCII letters, digits, `.`, `-`, `_`, or an
///   `IPv6` address in brackets) and an optional `:port` (1 to 65535). The
///   host is not empty and has no user information, `%` escape, path, query
///   or extension.
/// - `ldapi`: the socket path, `%`-escaped (`%2Frun%2Fldapi`) or empty (the
///   default socket); ASCII letters, digits, `.`, `-`, `_` and `%XX` only.
///
/// The scheme is read case-insensitively, like the client does.
fn parse_ldap_uri(uri: &str) -> Option<LdapTarget<'_>> {
    if uri.len() > LDAP_URI_MAX_LEN {
        return None;
    }
    let (scheme, rest) = uri.split_once("://")?;
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if scheme.eq_ignore_ascii_case("ldapi") {
        let bytes = authority.as_bytes();
        let mut i = 0;
        while let Some(&b) = bytes.get(i) {
            if b == b'%' {
                let hex = bytes.get(i + 1..i + 3)?;
                if !hex.iter().all(u8::is_ascii_hexdigit) {
                    return None;
                }
                i += 3;
            } else if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_') {
                i += 1;
            } else {
                return None;
            }
        }
        return Some(LdapTarget::Socket);
    }
    if !scheme.eq_ignore_ascii_case("ldap") && !scheme.eq_ignore_ascii_case("ldaps") {
        return None;
    }
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (address, after) = bracketed.split_once(']')?;
        address.parse::<Ipv6Addr>().ok()?;
        let port = if after.is_empty() {
            None
        } else {
            Some(after.strip_prefix(':')?)
        };
        (address, port)
    } else {
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };
        let name_like = !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
        if !name_like {
            return None;
        }
        (host, port)
    };
    if let Some(port) = port {
        let digits = !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit());
        if !digits || !port.parse::<u16>().is_ok_and(|p| p != 0) {
            return None;
        }
    }
    Some(LdapTarget::Network(host))
}

/// Whether `uri` designates the directory server of the SSH host itself, the
/// only one the host's stored TLS client certificate may be presented to:
/// an `ldapi://` socket, or an `ldap://` / `ldaps://` URI whose host is
/// `localhost` (any case) or a loopback IP address. A URI that is not a valid
/// one, and any other host (a `DNS` name can point anywhere), is another
/// server.
fn is_local_ldap_uri(uri: &str) -> bool {
    match parse_ldap_uri(uri) {
        Some(LdapTarget::Socket) => true,
        Some(LdapTarget::Network(host)) => is_loopback_host(host),
        None => false,
    }
}

/// The environment assignment that goes before the client program:
/// [`LDAP_REMOTE_ENV`] for a `uri` that is not a local server, nothing for a
/// local one and when there is no `uri` (the server of the host's `ldap.conf`,
/// chosen by the host, not by the caller).
fn client_env(uri: Option<&str>) -> &'static str {
    if uri.is_some_and(|u| !is_local_ldap_uri(u)) {
        LDAP_REMOTE_ENV
    } else {
        ""
    }
}

/// Builds LDAP CLI commands for remote execution.
pub struct LdapCommandBuilder;

impl LdapCommandBuilder {
    /// Build an ldapsearch command.
    ///
    /// `uri` is checked by [`Self::validate_uri`]. For a server other than the
    /// host's own, `LDAPTLS_CERT= LDAPTLS_KEY= ` goes before `ldapsearch`; without `uri`,
    /// and for a local server, the command is unchanged. The same holds for
    /// the other builders.
    #[must_use]
    pub fn build_search_command(
        base_dn: &str,
        filter: Option<&str>,
        attributes: Option<&str>,
        scope: Option<&str>,
        uri: Option<&str>,
    ) -> String {
        let mut cmd = format!("{}ldapsearch -x -LLL", client_env(uri));
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
        let mut cmd = format!("{}ldapadd -x", client_env(uri));
        if let Some(u) = uri {
            let _ = write!(cmd, " -H {}", shell_escape(u));
        }
        let escaped = shell_escape(ldif_content);
        format!("printf '%s' {escaped} | {cmd}")
    }

    /// Build an ldapmodify command (from LDIF on stdin).
    #[must_use]
    pub fn build_modify_command(ldif_content: &str, uri: Option<&str>) -> String {
        let mut cmd = format!("{}ldapmodify -x", client_env(uri));
        if let Some(u) = uri {
            let _ = write!(cmd, " -H {}", shell_escape(u));
        }
        let escaped = shell_escape(ldif_content);
        format!("printf '%s' {escaped} | {cmd}")
    }

    /// Check the `uri` of an LDAP tool: one `ldap://`, `ldaps://` or `ldapi://`
    /// URI of the form `scheme://host[:port]` (an `IPv6` address in brackets;
    /// `ldapi://` with the `%`-escaped socket path, or empty for the default
    /// one), at most 255 bytes. No list of URIs, spaces, commas, user
    /// information, path, query or extensions.
    ///
    /// A server other than the host's own (anything but `ldapi://` and
    /// `localhost` or a loopback address) is queried without the client
    /// certificate that the host's `ldaprc` names.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` naming `uri`.
    pub fn validate_uri(uri: &str) -> Result<()> {
        if parse_ldap_uri(uri).is_some() {
            Ok(())
        } else {
            Err(BridgeError::CommandDenied {
                reason: format!(
                    "'uri' must be one ldap://, ldaps:// or ldapi:// URI of the form \
                     scheme://host[:port] (IPv6 address in brackets; for ldapi:// %-escape the \
                     socket path: ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi, not ldapi:///var/run/...), \
                     at most {LDAP_URI_MAX_LEN} bytes, without spaces, commas, user \
                     information, path or query: omit 'uri' to use the server of the host's \
                     ldap.conf"
                ),
            })
        }
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

    // ===== uri: client certificate of the host =====

    const NO_CERT: &str = "LDAPTLS_CERT= LDAPTLS_KEY= ";

    const REMOTE_URIS: [&str; 12] = [
        "ldap://ldap.example.com",
        "ldaps://ldap.example.com:636",
        "LDAPS://Ldap.Example.com/",
        "ldap://10.0.0.5:389",
        "ldaps://[2001:db8::1]:636",
        "ldap://localhost.example.com",
        "ldap://localhost.",
        "ldap://127.1",
        "ldap://0.0.0.0",
        "ldaps://[::2]",
        "ldap://::1",
        "not a uri",
    ];

    const LOCAL_URIS: [&str; 11] = [
        "ldapi://",
        "ldapi:///",
        "ldapi://%2Frun%2Fslapd%2Fldapi",
        "LDAPI://%2fvar%2frun%2fldapi",
        "ldap://localhost",
        "ldaps://LOCALHOST:636",
        "ldap://127.0.0.1:389/",
        "ldaps://127.0.0.2",
        "ldap://[::1]",
        "ldaps://[::1]:636",
        "ldap://[::ffff:127.0.0.1]:389",
    ];

    #[test]
    fn test_search_golden_strings() {
        assert_eq!(
            LdapCommandBuilder::build_search_command("dc=x", None, None, None, None),
            "ldapsearch -x -LLL -b 'dc=x'"
        );
        assert_eq!(
            LdapCommandBuilder::build_search_command(
                "dc=example,dc=com",
                Some("(cn=a)"),
                Some("cn mail"),
                Some("sub"),
                Some("ldaps://ldap.example.com"),
            ),
            "LDAPTLS_CERT= LDAPTLS_KEY= ldapsearch -x -LLL -H 'ldaps://ldap.example.com' \
             -b 'dc=example,dc=com' -s 'sub' -- '(cn=a)' 'cn' 'mail'"
        );
        assert_eq!(
            LdapCommandBuilder::build_search_command(
                "dc=x",
                None,
                None,
                None,
                Some("ldapi://%2Frun%2Fslapd%2Fldapi"),
            ),
            "ldapsearch -x -LLL -H 'ldapi://%2Frun%2Fslapd%2Fldapi' -b 'dc=x'"
        );
        assert_eq!(
            LdapCommandBuilder::build_search_command(
                "dc=x",
                None,
                None,
                None,
                Some("ldap://localhost:389")
            ),
            "ldapsearch -x -LLL -H 'ldap://localhost:389' -b 'dc=x'"
        );
    }

    #[test]
    fn test_user_info_and_group_members_golden_strings() {
        assert_eq!(
            LdapCommandBuilder::build_user_info_command("dc=x", "jdoe", Some("ldap://10.0.0.5")),
            "LDAPTLS_CERT= LDAPTLS_KEY= ldapsearch -x -LLL -H 'ldap://10.0.0.5' -b 'dc=x' \
             -s 'sub' -- '(uid=jdoe)'"
        );
        assert_eq!(
            LdapCommandBuilder::build_user_info_command("dc=x", "jdoe", Some("ldap://127.0.0.1")),
            "ldapsearch -x -LLL -H 'ldap://127.0.0.1' -b 'dc=x' -s 'sub' -- '(uid=jdoe)'"
        );
        assert_eq!(
            LdapCommandBuilder::build_group_members_command(
                "dc=x",
                "ops",
                Some("ldaps://ldap.example.com")
            ),
            "LDAPTLS_CERT= LDAPTLS_KEY= ldapsearch -x -LLL -H 'ldaps://ldap.example.com' \
             -b 'dc=x' -s 'sub' -- '(cn=ops)' 'member' 'memberUid'"
        );
        assert_eq!(
            LdapCommandBuilder::build_group_members_command("dc=x", "ops", None),
            "ldapsearch -x -LLL -b 'dc=x' -s 'sub' -- '(cn=ops)' 'member' 'memberUid'"
        );
    }

    #[test]
    fn test_add_and_modify_golden_strings() {
        assert_eq!(
            LdapCommandBuilder::build_add_command("dn: cn=x", None),
            "printf '%s' 'dn: cn=x' | ldapadd -x"
        );
        assert_eq!(
            LdapCommandBuilder::build_add_command("dn: cn=x", Some("ldaps://ldap.example.com:636")),
            "printf '%s' 'dn: cn=x' | LDAPTLS_CERT= LDAPTLS_KEY= ldapadd -x \
             -H 'ldaps://ldap.example.com:636'"
        );
        assert_eq!(
            LdapCommandBuilder::build_add_command("dn: cn=x", Some("ldapi://")),
            "printf '%s' 'dn: cn=x' | ldapadd -x -H 'ldapi://'"
        );
        assert_eq!(
            LdapCommandBuilder::build_modify_command("dn: cn=x", None),
            "printf '%s' 'dn: cn=x' | ldapmodify -x"
        );
        assert_eq!(
            LdapCommandBuilder::build_modify_command("dn: cn=x", Some("ldap://ldap.example.com")),
            "printf '%s' 'dn: cn=x' | LDAPTLS_CERT= LDAPTLS_KEY= ldapmodify -x \
             -H 'ldap://ldap.example.com'"
        );
        assert_eq!(
            LdapCommandBuilder::build_modify_command("dn: cn=x", Some("ldaps://[::1]:636")),
            "printf '%s' 'dn: cn=x' | ldapmodify -x -H 'ldaps://[::1]:636'"
        );
    }

    #[test]
    fn test_every_builder_drops_the_host_client_certificate_for_another_server() {
        for uri in REMOTE_URIS {
            let u = Some(uri);
            let commands = [
                LdapCommandBuilder::build_search_command("dc=x", None, None, None, u),
                LdapCommandBuilder::build_user_info_command("dc=x", "a", u),
                LdapCommandBuilder::build_group_members_command("dc=x", "a", u),
                LdapCommandBuilder::build_add_command("dn: cn=x", u),
                LdapCommandBuilder::build_modify_command("dn: cn=x", u),
            ];
            for cmd in commands {
                assert!(cmd.contains(&format!("{NO_CERT}ldap")), "{uri}: {cmd}");
                assert!(!cmd.contains("-D") && !cmd.contains("-w"), "{uri}: {cmd}");
            }
        }
    }

    #[test]
    fn test_no_builder_adds_the_override_for_the_local_server() {
        for uri in LOCAL_URIS {
            let u = Some(uri);
            let commands = [
                LdapCommandBuilder::build_search_command("dc=x", None, None, None, u),
                LdapCommandBuilder::build_user_info_command("dc=x", "a", u),
                LdapCommandBuilder::build_group_members_command("dc=x", "a", u),
                LdapCommandBuilder::build_add_command("dn: cn=x", u),
                LdapCommandBuilder::build_modify_command("dn: cn=x", u),
            ];
            for cmd in commands {
                assert!(!cmd.contains("LDAPTLS"), "{uri}: {cmd}");
            }
        }
        let none = [
            LdapCommandBuilder::build_search_command("dc=x", None, None, None, None),
            LdapCommandBuilder::build_add_command("dn: cn=x", None),
            LdapCommandBuilder::build_modify_command("dn: cn=x", None),
        ];
        for cmd in none {
            assert!(!cmd.contains("LDAPTLS"), "{cmd}");
        }
    }

    #[test]
    fn test_no_builder_sets_trust_or_sasl_options() {
        let cmd = LdapCommandBuilder::build_search_command(
            "dc=x",
            None,
            None,
            None,
            Some("ldaps://ldap.example.com"),
        );
        for forbidden in [
            "CACERT",
            "REQCERT",
            "LDAPNOINIT",
            "SASL",
            " -Y",
            " -ZZ",
            " -D",
            " -w",
            " -W",
        ] {
            assert!(!cmd.contains(forbidden), "{forbidden}: {cmd}");
        }
    }

    #[test]
    fn test_is_local_ldap_uri() {
        for uri in LOCAL_URIS {
            assert!(is_local_ldap_uri(uri), "{uri}");
        }
        for uri in REMOTE_URIS {
            assert!(!is_local_ldap_uri(uri), "{uri}");
        }
    }

    #[test]
    fn test_validate_uri_accepts_one_uri() {
        for uri in LOCAL_URIS.iter().chain(&REMOTE_URIS[..10]) {
            assert!(LdapCommandBuilder::validate_uri(uri).is_ok(), "{uri}");
        }
        for uri in [
            "ldap://a_b.example.com:1",
            "ldaps://h:65535",
            "ldap://[::1]:389/",
        ] {
            assert!(LdapCommandBuilder::validate_uri(uri).is_ok(), "{uri}");
        }
    }

    #[test]
    fn test_validate_uri_refuses_everything_else() {
        let too_long = format!("ldap://{}", "a".repeat(LDAP_URI_MAX_LEN));
        for bad in [
            "",
            "ldap.example.com",
            "ldap://",
            "ldap:///",
            "ldaps://",
            "http://ldap.example.com",
            "ldap:/ldap.example.com",
            "ldap://a ldap://b",
            "ldap://a,ldap://b",
            "ldap://a\tldap://b",
            "ldap://a\nldap://b",
            " ldap://a",
            "ldap://a ",
            "ldap://user@ldap.example.com",
            "ldap://user:pw@ldap.example.com",
            "ldap://ldap.example.com//",
            "ldap://ldap.example.com/dc=x",
            "ldap://ldap.example.com/??sub",
            "ldap://ldap.example.com?",
            "ldap://ldap.example.com#x",
            "ldap://ldap.example.com\\x",
            "ldap://loc%61lhost",
            "ldap://host:",
            "ldap://host:0",
            "ldap://host:65536",
            "ldap://host:99999999999",
            "ldap://host:+389",
            "ldap://host:389:389",
            "ldap://host:ldap",
            "ldap://::1",
            "ldap://[::1",
            "ldap://[::1]x",
            "ldap://[::1]:",
            "ldap://[localhost]",
            "ldap://[fe80::1%eth0]",
            "ldap://\u{e9}.example.com",
            "ldap://$(id)",
            "ldap://a;id",
            "ldap://a`id`",
            "ldap://a'b",
            "ldapi://%2",
            "ldapi://%zz",
            "ldapi://a b",
            "ldapi://%2Frun/dc=x",
            "ldapi://a:b",
            "-H",
            "--",
            too_long.as_str(),
        ] {
            match LdapCommandBuilder::validate_uri(bad) {
                Err(BridgeError::CommandDenied { reason }) => {
                    assert!(reason.contains("'uri'"), "{bad:?}");
                    assert!(reason.contains("omit 'uri'"), "{bad:?}");
                }
                other => panic!("expected CommandDenied for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_validate_uri_refusal_tells_to_escape_the_ldapi_socket_path() {
        for bad in ["ldapi:///srv/x/ldapi", "ldapi://srv/x"] {
            match LdapCommandBuilder::validate_uri(bad) {
                Err(BridgeError::CommandDenied { reason }) => {
                    assert!(
                        reason.contains("%-escape the socket path"),
                        "{bad:?}: {reason}"
                    );
                    assert!(
                        reason.contains("ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi"),
                        "{bad:?}: {reason}"
                    );
                }
                other => panic!("expected CommandDenied for {bad:?}, got {other:?}"),
            }
        }
    }
}
