//! Oracles shared by the fuzz targets.
//!
//! A fuzz target that only checks "did not panic" cannot tell a builder that
//! quotes its inputs from one that pastes them in bare: neither panics, and
//! only one of them is safe. What separates them is whether the fuzzed input
//! survives the trip through the shell as *one word, unchanged* — so that is
//! what these oracles measure.

/// Split a POSIX shell command into words the way `/bin/sh` would, or `None`
/// when a control operator appears outside quotes.
///
/// This is deliberately **not** the inverse of
/// [`bridge_mcp::mcp::shell_escape`]. Mirroring the escape would make every
/// assertion a tautology: any bug reproduced in both halves cancels out. This
/// reads the string the way the shell does — quoting states, backslash,
/// operators — so it disagrees with a wrong escape.
///
/// `None` means the string is not a plain word list: something in it (`;`,
/// `|`, `&`, `` ` ``, `$(`, `<`, `>`, or a newline) would be read as syntax
/// rather than as text. For a command built from untrusted input, that is
/// exactly the outcome worth failing on — an operator can only appear there
/// if the builder put it there deliberately, never because a caller supplied
/// one.
///
/// Unsupported by design, because no builder in this crate emits them and
/// pretending otherwise would hide a real leak behind a permissive parser:
/// `$(...)`/`` `...` `` substitution, `${...}` expansion, here-documents.
/// Each is reported as an operator, not silently accepted.
#[must_use]
pub fn shell_words(input: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut has_word = false;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            // Unquoted whitespace ends the current word.
            ' ' | '\t' => {
                if has_word {
                    words.push(std::mem::take(&mut cur));
                    has_word = false;
                }
            }
            // Control operators and expansions: this is not a plain word list.
            ';' | '|' | '&' | '<' | '>' | '`' | '\n' | '\r' | '(' | ')' => return None,
            '$' => return None,
            // Single quotes: everything is literal until the closing quote.
            '\'' => {
                has_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        // An unterminated quote is not a word list either: the
                        // shell would keep reading past the end of the command.
                        None => return None,
                        Some(q) => cur.push(q),
                    }
                }
            }
            // Double quotes: literal except backslash and the expansions we
            // refuse above.
            '"' => {
                has_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('$' | '`') => return None,
                        Some('\\') => match chars.next() {
                            Some(e) => cur.push(e),
                            None => return None,
                        },
                        None => return None,
                        Some(q) => cur.push(q),
                    }
                }
            }
            // Backslash quotes the next character, whatever it is.
            '\\' => {
                has_word = true;
                match chars.next() {
                    Some(e) => cur.push(e),
                    None => return None,
                }
            }
            other => {
                has_word = true;
                cur.push(other);
            }
        }
    }

    if has_word {
        words.push(cur);
    }
    Some(words)
}

/// Assert that `needle` reached `command` as one intact word and nothing else.
///
/// This is the property a command builder owes its caller: the value the
/// caller passed is the value the remote program receives — not a fragment of
/// it, not it plus a neighbouring token, and above all not a piece of shell
/// syntax.
///
/// Panics with the built command in the message, because the command is the
/// evidence: a report saying only "input was accepted" leaves the reader to
/// guess where in the line it landed.
///
/// # Panics
///
/// Panics when `command` is not a plain word list, or when no word equals
/// `needle`.
pub fn assert_survives_as_one_word(command: &str, needle: &str, context: &str) {
    let Some(words) = shell_words(command) else {
        panic!(
            "{context}: input {needle:?} produced a command carrying shell syntax; \
             built: {command:?}"
        );
    };
    assert!(
        words.iter().any(|w| w == needle),
        "{context}: input {needle:?} did not survive as one word; \
         got words {words:?} from {command:?}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_quoted_word_keeps_its_metacharacters() {
        assert_eq!(
            shell_words("ls '; rm -rf /'").as_deref(),
            Some(&["ls".to_string(), "; rm -rf /".to_string()][..])
        );
    }

    #[test]
    fn posix_escape_of_a_quote_round_trips() {
        // The exact shape `shell_escape` emits for `it's`.
        assert_eq!(
            shell_words(r"'it'\''s'").as_deref(),
            Some(&["it's".to_string()][..])
        );
    }

    #[test]
    fn a_bare_operator_is_refused() {
        assert!(shell_words("ls; id").is_none());
        assert!(shell_words("ls | id").is_none());
        assert!(shell_words("echo $(id)").is_none());
        assert!(shell_words("echo `id`").is_none());
        assert!(shell_words("cat </etc/passwd").is_none());
    }

    #[test]
    fn an_unterminated_quote_is_refused() {
        assert!(shell_words("ls 'oops").is_none());
        assert!(shell_words("ls \"oops").is_none());
        assert!(shell_words("ls \\").is_none());
    }

    #[test]
    fn an_empty_quoted_word_is_still_a_word() {
        assert_eq!(
            shell_words("ls ''").as_deref(),
            Some(&["ls".to_string(), String::new()][..])
        );
    }

    #[test]
    fn one_word_survival_is_detected_both_ways() {
        assert_survives_as_one_word("show interfaces 'eth0'", "eth0", "ok");
        let leaked = std::panic::catch_unwind(|| {
            assert_survives_as_one_word("show interfaces eth0; id", "eth0; id", "leak");
        });
        assert!(leaked.is_err(), "a bare operator must fail the oracle");
    }
}

/// A command split into what the shell reads as *syntax* and what it reads as
/// *text*.
///
/// [`shell_words`] answers the question for a builder that emits a single
/// command. Most builders here emit a pipeline — `ls -la 'X' 2>/dev/null || ls
/// -la /etc/nginx/conf.d/ || echo 'none'` — where operators are deliberate and
/// `shell_words` correctly refuses. For those, the property is not "no
/// operators" but "no operator the CALLER put there", which needs the two
/// halves separated.
#[derive(Debug, PartialEq, Eq)]
pub struct ShellShape {
    /// The command with every maximal run of literal text replaced by `\0`.
    ///
    /// Two commands built from different inputs must have the SAME skeleton:
    /// that is precisely the statement that neither input contributed syntax.
    pub skeleton: String,
    /// The literal runs, in order, with quoting and escaping resolved — what
    /// the invoked program actually receives.
    pub literals: Vec<String>,
}

/// Scan `command` the way `/bin/sh` does, separating syntax from text.
///
/// Returns `None` when the command cannot be scanned at all — an unterminated
/// quote or a trailing backslash — which is itself a failure worth reporting,
/// since no builder should emit one.
#[must_use]
pub fn shell_shape(command: &str) -> Option<ShellShape> {
    let mut skeleton = String::new();
    let mut literals = Vec::new();
    let mut cur = String::new();
    let mut in_literal = false;
    let mut chars = command.chars().peekable();

    // Close the current literal run, if any, and mark it in the skeleton.
    macro_rules! flush {
        () => {
            if in_literal {
                literals.push(std::mem::take(&mut cur));
                skeleton.push('\0');
                in_literal = false;
            }
        };
    }

    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_literal = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        None => return None,
                        Some(q) => cur.push(q),
                    }
                }
            }
            '"' => {
                in_literal = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        // An expansion inside double quotes is syntax, not
                        // text: the shell will run or substitute it.
                        Some(e @ ('$' | '`')) => {
                            flush!();
                            skeleton.push(e);
                        }
                        Some('\\') => match chars.next() {
                            Some(e) => {
                                in_literal = true;
                                cur.push(e);
                            }
                            None => return None,
                        },
                        None => return None,
                        Some(q) => cur.push(q),
                    }
                }
            }
            '\\' => match chars.next() {
                Some(e) => {
                    in_literal = true;
                    cur.push(e);
                }
                None => return None,
            },
            // Everything the shell acts on rather than passes along.
            ';' | '|' | '&' | '<' | '>' | '(' | ')' | '`' | '$' | '\n' | '\r' | ' ' | '\t' => {
                flush!();
                skeleton.push(c);
            }
            other => {
                in_literal = true;
                cur.push(other);
            }
        }
    }
    flush!();

    Some(ShellShape {
        skeleton,
        literals,
    })
}

/// Assert that swapping `benign` for `hostile` changed the command's text and
/// nothing else.
///
/// This is the property a builder that emits a pipeline owes its caller. The
/// operators in the output are the builder's own and are meant to be there;
/// what must never happen is the CALLER adding one. Comparing skeletons says
/// exactly that, and says it without the target needing to know which
/// operators the builder legitimately emits.
///
/// # Panics
///
/// Panics when either command is unscannable, or when the skeletons differ.
pub fn assert_same_shell_skeleton(benign_cmd: &str, hostile_cmd: &str, context: &str) {
    let (Some(benign), Some(hostile)) = (shell_shape(benign_cmd), shell_shape(hostile_cmd)) else {
        panic!("{context}: emitted a command line sh cannot parse: {hostile_cmd:?}");
    };
    assert_eq!(
        benign.skeleton, hostile.skeleton,
        "{context}: the input changed the SHELL SKELETON, so it contributed syntax.\n  \
         benign : {benign_cmd:?}\n  hostile: {hostile_cmd:?}"
    );
}

#[cfg(test)]
mod shape_tests {
    use super::*;

    #[test]
    fn a_pipeline_keeps_its_own_operators() {
        let shape = shell_shape("ls -la '/etc/nginx' 2>/dev/null || echo 'none'").unwrap();
        assert_eq!(shape.skeleton, "\0 \0 \0 \0>\0 || \0 \0");
        assert_eq!(
            shape.literals,
            vec!["ls", "-la", "/etc/nginx", "2", "/dev/null", "echo", "none"]
        );
    }

    /// The whole point: a quoted hostile value must not move the skeleton.
    #[test]
    fn a_quoted_hostile_value_does_not_change_the_skeleton() {
        assert_same_shell_skeleton(
            "ls -la 'safe' 2>/dev/null",
            "ls -la '; rm -rf /' 2>/dev/null",
            "quoted",
        );
    }

    /// And an unquoted one must.
    #[test]
    fn an_unquoted_hostile_value_does_change_the_skeleton() {
        let caught = std::panic::catch_unwind(|| {
            assert_same_shell_skeleton("ls -la safe", "ls -la ; rm -rf /", "bare");
        });
        assert!(caught.is_err(), "a bare operator must move the skeleton");
    }

    #[test]
    fn an_unterminated_quote_is_unscannable() {
        assert!(shell_shape("ls 'oops").is_none());
        assert!(shell_shape("ls \\").is_none());
    }
}
