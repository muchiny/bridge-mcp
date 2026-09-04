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

/// A NUL in the caller's value does NOT corrupt a skeleton comparison.
    ///
    /// Worth pinning because the plan this work follows says the opposite —
    /// it records `assert_same_shell_skeleton` as unusable when the value may
    /// contain a NUL, "because `\0` is `shell_shape`'s own skeleton marker".
    /// Measured here, it is not: the two NULs never meet. The skeleton only
    /// ever receives a `\0` from `flush!`, one per literal RUN, while a NUL in
    /// the input falls through to `other => cur.push(other)` and lands in
    /// `literals`. So the skeletons still match and the value still comes back
    /// whole.
    ///
    /// This is what lets the twenty command-builder targets use the skeleton
    /// oracle for the pipelines they emit, instead of being restricted to
    /// [`assert_survives_as_one_word`], which refuses any operator at all.
    #[test]
    fn a_nul_in_the_value_does_not_move_the_skeleton() {
        // POSIX escape of a value containing a NUL.
        let esc = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
        let benign = format!("cat {} 2>/dev/null || echo 'none'", esc("safe"));
        let hostile = format!("cat {} 2>/dev/null || echo 'none'", esc("a\0b"));
        let b = shell_shape(&benign).expect("benign scannable");
        let h = shell_shape(&hostile).expect("hostile scannable");
        assert_eq!(
            b.skeleton, h.skeleton,
            "a NUL in the value moved the skeleton"
        );
        let only = format!("cat {} 2>/dev/null || echo 'none'", esc("\0"));
        assert_eq!(
            b.skeleton,
            shell_shape(&only).unwrap().skeleton,
            "a lone NUL moved it"
        );
        assert!(
            h.literals.iter().any(|l| l == "a\0b"),
            "the value did not come back whole: {:?}",
            h.literals
        );
    }


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

// ===========================================================================
// PowerShell
// ===========================================================================
//
// Everything above reads `/bin/sh`. Eight of this crate's command builders do
// not target `/bin/sh` — `active_directory`, `hyperv`, `iis`,
// `scheduled_task`, `windows_event`, `windows_firewall`, `windows_registry`
// and `windows_service` all escape through
// `shell::escape(s, ShellType::PowerShell)`.
//
// The two shells differ on exactly one rule, and it is the one that matters
// here. POSIX closes the quote to embed a quote:
//
// ```text
// POSIX      : it's  ->  'it'\''s'
// PowerShell : it's  ->  'it''s'
// ```
//
// Handing the second to [`shell_words`] yields `["its"]` — it reads `'it'` as
// a finished word and `'s'` as a continuation, silently dropping the
// apostrophe. So the POSIX oracle would report "did not survive as one word"
// for every value containing a quote, on HEALTHY code, which is the failure
// this project has already paid for three times: an assertion that is red on
// working code teaches its reader to ignore red.
//
// These are separate functions rather than a `shell` parameter threaded
// through the ones above, deliberately. Six targets already depend on the
// POSIX pair; a shared scanner that had to answer for both dialects would put
// their behaviour one refactor away from the Windows rules, and nothing in the
// type system would notice.

/// Split a `PowerShell` command into words, or `None` when a control operator
/// appears outside quotes.
///
/// The mirror of [`shell_words`] for `pwsh`. Differences from POSIX, all of
/// them consequences of PowerShell's own grammar rather than choices:
///
/// * inside single quotes, `''` is a literal quote — there is no backslash
///   escape at all, and a backslash is an ordinary character (which is what
///   makes `'C:\Windows'` work);
/// * the escape character outside and inside double quotes is the BACKTICK,
///   not the backslash;
/// * `@` and `,` are operators (`@{...}`, `@(...)`, and the comma that builds
///   an array in `Select-Object Name,Status`).
#[must_use]
pub fn powershell_words(input: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut has_word = false;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' => {
                if has_word {
                    words.push(std::mem::take(&mut cur));
                    has_word = false;
                }
            }
            // Control operators and expansions: not a plain word list.
            ';' | '|' | '&' | '<' | '>' | '\n' | '\r' | '(' | ')' | '{' | '}' | '@' | ','
            | '$' => return None,
            // Single quotes: everything literal, `''` is one quote.
            '\'' => {
                has_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => {
                            if chars.peek() == Some(&'\'') {
                                chars.next();
                                cur.push('\'');
                            } else {
                                break;
                            }
                        }
                        None => return None,
                        Some(q) => cur.push(q),
                    }
                }
            }
            // Double quotes: expansions are syntax, backtick escapes.
            '"' => {
                has_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('$') => return None,
                        Some('`') => match chars.next() {
                            Some(e) => cur.push(e),
                            None => return None,
                        },
                        None => return None,
                        Some(q) => cur.push(q),
                    }
                }
            }
            // Backtick quotes the next character, whatever it is.
            '`' => {
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

/// Scan a `PowerShell` command the way `pwsh` does, separating syntax from
/// text. The mirror of [`shell_shape`].
#[must_use]
pub fn powershell_shape(command: &str) -> Option<ShellShape> {
    let mut skeleton = String::new();
    let mut literals = Vec::new();
    let mut cur = String::new();
    let mut in_literal = false;
    let mut chars = command.chars().peekable();

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
                        Some('\'') => {
                            if chars.peek() == Some(&'\'') {
                                chars.next();
                                cur.push('\'');
                            } else {
                                break;
                            }
                        }
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
                        // An expansion inside double quotes is syntax.
                        Some('$') => {
                            flush!();
                            skeleton.push('$');
                        }
                        Some('`') => match chars.next() {
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
            '`' => match chars.next() {
                Some(e) => {
                    in_literal = true;
                    cur.push(e);
                }
                None => return None,
            },
            ';' | '|' | '&' | '<' | '>' | '(' | ')' | '{' | '}' | '@' | ',' | '$' | '\n'
            | '\r' | ' ' | '\t' => {
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

/// [`assert_survives_as_one_word`], for a `PowerShell` command line.
///
/// # Panics
///
/// Panics when `command` is not a plain word list, or when no word equals
/// `needle`.
pub fn assert_survives_as_one_word_ps(command: &str, needle: &str, context: &str) {
    let Some(words) = powershell_words(command) else {
        panic!(
            "{context}: input {needle:?} produced a PowerShell command carrying \
             syntax; built: {command:?}"
        );
    };
    assert!(
        words.iter().any(|w| w == needle),
        "{context}: input {needle:?} did not survive as one word; \
         got words {words:?} from {command:?}"
    );
}

/// [`assert_same_shell_skeleton`], for a `PowerShell` command line.
///
/// # Panics
///
/// Panics when either command is unscannable, or when the skeletons differ.
pub fn assert_same_powershell_skeleton(benign_cmd: &str, hostile_cmd: &str, context: &str) {
    let (Some(benign), Some(hostile)) = (
        powershell_shape(benign_cmd),
        powershell_shape(hostile_cmd),
    ) else {
        panic!("{context}: emitted a PowerShell line pwsh cannot parse: {hostile_cmd:?}");
    };
    assert_eq!(
        benign.skeleton, hostile.skeleton,
        "{context}: the input changed the SHELL SKELETON, so it contributed syntax.\n  \
         benign : {benign_cmd:?}\n  hostile: {hostile_cmd:?}"
    );
}

/// Assert that `needle` reached `command` as TEXT: whole, inside one literal
/// run, having contributed no shell syntax.
///
/// This is [`assert_survives_as_one_word`] generalised to the builders that
/// emit pipelines, and it is the oracle the twenty command-builder targets
/// use. Three properties in one comparison:
///
/// * the command is scannable at all — an unterminated quote is its own
///   defect, and no builder should emit one;
/// * `needle` appears inside a single literal run, so it did not get split by
///   an operator, a space, or a quote boundary. A builder that pastes
///   `a; rm -rf /` in bare puts the `;` in the SKELETON and leaves `a` and
///   `rm` in different runs, so no run can contain the needle;
/// * and it is `contains`, not equality, on purpose: a value legitimately
///   lands inside a larger word (`--filter=name=VALUE`, `*VALUE*`), and
///   demanding a whole word there would be red on healthy code. Nothing is
///   lost — an operator still splits the run whatever surrounds it.
///
/// Refusal is always acceptable: a builder that returns `Err` for a hostile
/// value never reaches here. The fuzzer is looking for values that get
/// THROUGH.
///
/// # Panics
///
/// Panics when `command` cannot be scanned, or when no literal run contains
/// `needle`.
pub fn assert_arrives_as_text(command: &str, needle: &str, context: &str) {
    let Some(shape) = shell_shape(command) else {
        panic!("{context}: emitted a command line sh cannot parse: {command:?}");
    };
    assert!(
        shape.literals.iter().any(|l| l.contains(needle)),
        "{context}: input {needle:?} did not arrive as text — no literal run \
         contains it, so it was split by syntax the caller supplied.\n  \
         built    : {command:?}\n  skeleton : {:?}\n  literals : {:?}",
        shape.skeleton,
        shape.literals
    );
}

/// [`assert_arrives_as_text`], for a `PowerShell` command line.
///
/// # Panics
///
/// Panics when `command` cannot be scanned, or when no literal run contains
/// `needle`.
pub fn assert_arrives_as_text_ps(command: &str, needle: &str, context: &str) {
    let Some(shape) = powershell_shape(command) else {
        panic!("{context}: emitted a PowerShell line pwsh cannot parse: {command:?}");
    };
    assert!(
        shape.literals.iter().any(|l| l.contains(needle)),
        "{context}: input {needle:?} did not arrive as text — no literal run \
         contains it, so it was split by syntax the caller supplied.\n  \
         built    : {command:?}\n  skeleton : {:?}\n  literals : {:?}",
        shape.skeleton,
        shape.literals
    );
}

#[cfg(test)]
mod arrival_tests {
    use super::*;

    #[test]
    fn an_escaped_value_arrives_whole() {
        assert_arrives_as_text("git log --author='a; id' -n 10", "a; id", "posix");
        assert_arrives_as_text_ps("Get-Service -Name 'a; id' | Format-List", "a; id", "ps");
    }

    #[test]
    fn a_value_inside_a_larger_word_still_arrives() {
        assert_arrives_as_text("docker ps --filter 'name=a; id'", "a; id", "embedded");
    }

    #[test]
    fn a_bare_value_is_caught() {
        let caught = std::panic::catch_unwind(|| {
            assert_arrives_as_text("git log --author=a; id -n 10", "a; id", "bare");
        });
        assert!(caught.is_err(), "a bare operator must fail the oracle");
        let caught_ps = std::panic::catch_unwind(|| {
            assert_arrives_as_text_ps("Get-Service -Name a; id", "a; id", "bare");
        });
        assert!(caught_ps.is_err(), "a bare operator must fail the PowerShell oracle");
    }

    /// The PowerShell doubling rule, end to end through the arrival oracle.
    #[test]
    fn a_powershell_quote_arrives_whole() {
        // `shell::escape("it's", PowerShell)` == `'it''s'`
        assert_arrives_as_text_ps("Get-Service -Name 'it''s'", "it's", "quote");
    }
}

#[cfg(test)]
mod powershell_tests {
    use super::*;

    /// The rule the whole module exists for: `''` is one literal quote, and
    /// the POSIX reader gets it wrong.
    #[test]
    fn a_doubled_quote_is_one_quote() {
        // Exactly what `shell::escape(s, ShellType::PowerShell)` emits.
        assert_eq!(
            powershell_words("'it''s'").as_deref(),
            Some(&["it's".to_string()][..])
        );
        // And the POSIX reader silently drops it — this is the false positive
        // that would have been shipped by reusing `shell_words` here.
        assert_eq!(
            shell_words("'it''s'").as_deref(),
            Some(&["its".to_string()][..])
        );
    }

    #[test]
    fn a_trailing_quote_survives() {
        // `shell::escape("a'", PowerShell)` == `'a'''`
        assert_eq!(
            powershell_words("'a'''").as_deref(),
            Some(&["a'".to_string()][..])
        );
    }

    #[test]
    fn a_backslash_is_an_ordinary_character() {
        assert_eq!(
            powershell_words(r"'C:\Windows\Temp'").as_deref(),
            Some(&[r"C:\Windows\Temp".to_string()][..])
        );
    }

    #[test]
    fn a_bare_operator_is_refused() {
        assert!(powershell_words("Get-Service | Format-List").is_none());
        assert!(powershell_words("Stop-Service -Name x; id").is_none());
        assert!(powershell_words("echo $(id)").is_none());
        assert!(powershell_words("Select-Object Name,Status").is_none());
        assert!(powershell_words("@{a=1}").is_none());
    }

    #[test]
    fn an_unterminated_quote_is_refused() {
        assert!(powershell_words("Get-Service 'oops").is_none());
        assert!(powershell_words("Get-Service \"oops").is_none());
        assert!(powershell_words("Get-Service `").is_none());
    }

    #[test]
    fn a_pipeline_keeps_its_own_operators() {
        let shape =
            powershell_shape("Get-Service -Name 'x' | Select-Object Name,Status").unwrap();
        assert_eq!(shape.skeleton, "\0 \0 \0 | \0 \0,\0");
        assert_eq!(
            shape.literals,
            vec!["Get-Service", "-Name", "x", "Select-Object", "Name", "Status"]
        );
    }

    /// A hostile value stays inside its quotes and moves nothing.
    #[test]
    fn a_quoted_hostile_value_does_not_change_the_skeleton() {
        assert_same_powershell_skeleton(
            "Stop-Service -Name 'safe' -Force",
            "Stop-Service -Name '; Remove-Item C:\\ -Recurse' -Force",
            "quoted",
        );
    }

    /// And an unquoted one must.
    #[test]
    fn an_unquoted_hostile_value_does_change_the_skeleton() {
        let caught = std::panic::catch_unwind(|| {
            assert_same_powershell_skeleton(
                "Stop-Service -Name safe",
                "Stop-Service -Name ; Remove-Item C:\\",
                "bare",
            );
        });
        assert!(caught.is_err(), "a bare operator must move the skeleton");
    }

    #[test]
    fn one_word_survival_is_detected_both_ways() {
        assert_survives_as_one_word_ps("Get-Service -Name 'eth0'", "eth0", "ok");
        let leaked = std::panic::catch_unwind(|| {
            assert_survives_as_one_word_ps("Get-Service -Name eth0; id", "eth0; id", "leak");
        });
        assert!(leaked.is_err(), "a bare operator must fail the oracle");
    }
}
