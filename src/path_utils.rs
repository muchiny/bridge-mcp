//! Tilde-expansion helper. Replaces the archived `shellexpand` crate.
//!
//! `shellexpand` was archived upstream on 2026-02-25 and no longer
//! receives security patches. We only ever used `shellexpand::tilde`
//! (`~` and `~/...` expansion), so a thin `dirs::home_dir`-based
//! wrapper covers all real usage at the 9 call sites that remain in
//! the tree (CLI, config loader, SSH client, and three file-transfer
//! tool handlers).
//!
//! User-specific expansion (`~user/...`) is intentionally NOT
//! supported — the original `shellexpand::tilde` does not consult
//! `/etc/passwd` either, so this is a behaviour-preserving choice.

use std::path::PathBuf;

/// Replace a leading `~` with the user's home directory.
///
/// Returns `Some(<home>)` for `~`, `Some(<home>/rest)` for `~/rest`,
/// and `Some(input)` for everything else (relative paths, absolute
/// paths, and `~user/...` which we do not enumerate). Returns `None`
/// only when the input begins with `~`/`~/` *and* the OS cannot
/// resolve a home directory — extremely rare on real systems but
/// possible in stripped containers or embedded environments.
#[must_use]
pub fn home_expand(input: &str) -> Option<PathBuf> {
    if input == "~" {
        return dirs::home_dir();
    }
    if let Some(rest) = input.strip_prefix("~/") {
        return dirs::home_dir().map(|h| h.join(rest));
    }
    Some(PathBuf::from(input))
}

/// Convenience: home-expand then convert to a string. Lossy if the
/// resolved path contains non-UTF-8 bytes (very rare on modern
/// systems where home directories are UTF-8 paths).
#[must_use]
pub fn home_expand_string(input: &str) -> Option<String> {
    home_expand(input).map(|p| p.to_string_lossy().into_owned())
}

/// Best-effort variant: returns the expanded path as a `String`,
/// falling back to the input unchanged if home resolution fails.
///
/// Use this in code paths that previously called
/// `shellexpand::tilde(p).to_string()` — `shellexpand` never failed,
/// so dropping it must not introduce a new error path. The fallback
/// matches the historical behaviour: if the home directory cannot be
/// resolved, the (non-expanded) input is passed through and the
/// downstream `Path::exists()` / `open()` will fail naturally with a
/// clear filesystem error.
#[must_use]
pub fn home_expand_or_input(input: &str) -> String {
    home_expand_string(input).unwrap_or_else(|| input.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_expand_replaces_leading_tilde() {
        let home = std::env::var("HOME").expect("HOME must be set in test environment");
        assert_eq!(
            home_expand("~/foo"),
            Some(PathBuf::from(format!("{home}/foo")))
        );
        assert_eq!(home_expand("~"), Some(PathBuf::from(&home)));
    }

    #[test]
    fn home_expand_passes_through_absolute() {
        assert_eq!(
            home_expand("/abs/path"),
            Some(PathBuf::from("/abs/path"))
        );
        assert_eq!(
            home_expand("relative/path"),
            Some(PathBuf::from("relative/path"))
        );
    }

    #[test]
    fn home_expand_does_not_handle_user_specific() {
        // `~bob/foo` is returned unchanged: we don't enumerate
        // /etc/passwd, matching `shellexpand::tilde`'s own behaviour.
        assert_eq!(
            home_expand("~bob/foo"),
            Some(PathBuf::from("~bob/foo"))
        );
    }

    #[test]
    fn home_expand_string_replaces_leading_tilde() {
        let home = std::env::var("HOME").expect("HOME must be set in test environment");
        assert_eq!(
            home_expand_string("~/foo").as_deref(),
            Some(format!("{home}/foo").as_str())
        );
    }

    #[test]
    fn home_expand_or_input_falls_back_on_unchanged_value() {
        // For inputs without `~`, the helper is a no-op.
        assert_eq!(home_expand_or_input("/etc/ssh/sshd_config"), "/etc/ssh/sshd_config");
        assert_eq!(home_expand_or_input("relative"), "relative");
    }

    #[test]
    fn home_expand_or_input_expands_tilde_when_home_known() {
        let home = std::env::var("HOME").expect("HOME must be set in test environment");
        assert_eq!(home_expand_or_input("~/.ssh/id_ed25519"), format!("{home}/.ssh/id_ed25519"));
    }
}
