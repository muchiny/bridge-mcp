//! Every tool, every string argument, two hostile values: the commands that
//! reach the executor must keep each value one quoted word.
//!
//! The tools build their commands by hand, one `format!` at a time, and a
//! review of 400 builders keeps finding the same three mistakes: a value
//! spliced raw, a value quoted and then wrapped in a second pair of quotes
//! (which cancels the first), and a quoted value in a positional slot where
//! the program reads it as an option. Each was a command injection or worse.
//! This sweep finds them mechanically: it calls every registered tool through
//! the real pipeline with a mock executor, once per string argument with
//! [`METACHARS`] and once with [`DASHED`], then lexes each command the mock
//! received as a POSIX shell would and checks where the value landed.
//!
//! What it cannot see: a value a second program parses with its own grammar
//! (an `awk` program, SQL, a crontab line, LDIF, JSON read by `jq`), and a
//! value written to a file that something else executes later. Those need
//! their own tests.

use std::fmt::Write as _;

use serde_json::{Value, json};

use crate::mcp::tool_handlers::utils::guard_test_support::minimal_value;
use crate::ports::ToolContext;

/// The marker every hostile value starts with; it survives any quoting, so
/// counting it in the raw command counts the places the value went.
const MARK: &str = "ZQX";

/// A value made of the characters a POSIX shell treats specially.
const METACHARS: &str = "ZQXa'b\"c;d|e&f$(g)h`i\\j k#l<m>n*o?p~q{r}s!tZQY";

/// A value a program would read as an option if it sat in a positional slot.
const DASHED: &str = "-ZQXdash";

/// Tools the sweep does not call: they open real connections (SFTP, a
/// persistent shell, a tunnel) or read and write local files and state.
const SKIPPED_TOOLS: &[&str] = &[
    "ssh_upload",
    "ssh_download",
    "ssh_sync",
    "ssh_ls",
    "ssh_files_write",
    "ssh_config_set",
    "ssh_config_get",
];
const SKIPPED_PREFIXES: &[&str] = &["ssh_session_", "ssh_tunnel_", "ssh_recording_"];

/// Arguments the sweep never sets: routing, and local side effects.
const SKIPPED_ARGS: &[&str] = &["host", "hosts", "save_output"];

/// How an argument that is a script by design may land.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Raw {
    /// The value is the whole command: the validator governs it, not quoting.
    Whole,
    /// The value is a script run somewhere else (in a container, a pod): it
    /// must reach that `sh -c` as one quoted word, and its content is not
    /// checked again.
    Inner,
    /// The value is a list of options by design: it must stay one quoted
    /// word, and it may start with `-`.
    Options,
}

/// Arguments that are a script by design, with what governs them instead of
/// quoting. Every other argument must stay one quoted word.
const RAW_BY_DESIGN: &[(&str, &str, Raw)] = &[
    ("ssh_exec", "command", Raw::Whole),
    ("ssh_exec_multi", "command", Raw::Whole),
    ("ssh_canary_exec", "command", Raw::Whole),
    ("ssh_canary_exec", "health_check", Raw::Whole),
    ("ssh_rolling_exec", "command", Raw::Whole),
    ("ssh_rolling_exec", "health_check", Raw::Whole),
    ("ssh_fleet_diff", "command", Raw::Whole),
    ("ssh_pty_exec", "command", Raw::Whole),
    ("ssh_docker_exec", "command", Raw::Inner),
    ("ssh_podman_exec", "command", Raw::Inner),
    ("ssh_crictl_exec", "command", Raw::Inner),
    ("ssh_k8s_exec", "command", Raw::Inner),
    // `--region eu-west-1 --output json`, as the schema documents.
    ("ssh_aws_cli", "args", Raw::Options),
    // Device CLI text for a host tagged `network-equipment`, not a shell.
    ("ssh_net_equip_config", "commands", Raw::Whole),
];

fn raw_kind(tool: &str, arg: &str) -> Option<Raw> {
    RAW_BY_DESIGN
        .iter()
        .find(|(t, a, _)| *t == tool && *a == arg)
        .map(|&(_, _, k)| k)
}

/// One character of a lexed word, and whether quoting made it literal.
type Word = Vec<(char, bool)>;

#[derive(Debug)]
enum Tok {
    Word(Word),
    /// `;`, `&`, `|`, `(`, `)`, `<`, `>` or a newline (`<` for `<<`).
    Op(char),
}

/// Lex `src` as a POSIX shell would: words with per-character quoting,
/// operators, comments, backslash escapes, `'…'`, `"…"` (where `$` and a
/// backtick stay active) and here-documents.
#[expect(
    clippy::too_many_lines,
    reason = "one state machine; splitting it would scatter the quoting rules"
)]
fn lex(src: &str) -> Result<Vec<Tok>, String> {
    let chars: Vec<char> = src.chars().collect();
    let mut toks = Vec::new();
    let mut word: Word = Vec::new();
    let mut in_word = false;
    // Here-documents opened on the current line: (delimiter, quoted, strip tabs).
    let mut pending: Vec<(String, bool, bool)> = Vec::new();
    let mut i = 0;
    let flush = |toks: &mut Vec<Tok>, word: &mut Word, in_word: &mut bool| {
        if *in_word {
            toks.push(Tok::Word(std::mem::take(word)));
            *in_word = false;
        }
    };
    while i < chars.len() {
        let c = chars[i];
        match c {
            ' ' | '\t' => {
                flush(&mut toks, &mut word, &mut in_word);
                i += 1;
            }
            '\n' => {
                flush(&mut toks, &mut word, &mut in_word);
                toks.push(Tok::Op('\n'));
                i += 1;
                for (delim, quoted, strip) in std::mem::take(&mut pending) {
                    let mut body: Word = Vec::new();
                    loop {
                        if i >= chars.len() {
                            return Err(format!("here-document `{delim}` never ends"));
                        }
                        let end = chars[i..]
                            .iter()
                            .position(|&c| c == '\n')
                            .map_or(chars.len(), |p| i + p);
                        let line: String = chars[i..end].iter().collect();
                        let cmp = if strip {
                            line.trim_start_matches('\t')
                        } else {
                            line.as_str()
                        };
                        i = (end + 1).min(chars.len());
                        if cmp == delim {
                            break;
                        }
                        for ch in line.chars().chain(std::iter::once('\n')) {
                            body.push((ch, quoted || !matches!(ch, '$' | '`' | '\\')));
                        }
                    }
                    toks.push(Tok::Word(body));
                }
            }
            '<' if chars.get(i + 1) == Some(&'<') && chars.get(i + 2) != Some(&'<') => {
                flush(&mut toks, &mut word, &mut in_word);
                toks.push(Tok::Op('<'));
                i += 2;
                let strip = chars.get(i) == Some(&'-');
                if strip {
                    i += 1;
                }
                while chars.get(i) == Some(&' ') {
                    i += 1;
                }
                let start = i;
                while i < chars.len()
                    && !matches!(
                        chars[i],
                        ' ' | '\t' | '\n' | ';' | '&' | '|' | '<' | '>' | '(' | ')'
                    )
                {
                    i += 1;
                }
                let raw: String = chars[start..i].iter().collect();
                let quoted = raw.contains(['\'', '"', '\\']);
                let delim: String = raw
                    .chars()
                    .filter(|c| !matches!(c, '\'' | '"' | '\\'))
                    .collect();
                if delim.is_empty() {
                    return Err("here-document without a delimiter".to_string());
                }
                pending.push((delim, quoted, strip));
            }
            ';' | '&' | '|' | '(' | ')' | '<' | '>' => {
                flush(&mut toks, &mut word, &mut in_word);
                toks.push(Tok::Op(c));
                i += 1;
            }
            '#' if !in_word => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '\\' => {
                match chars.get(i + 1) {
                    Some('\n') | None => {}
                    Some(&next) => {
                        word.push((next, true));
                        in_word = true;
                    }
                }
                i += 2;
            }
            '\'' => {
                in_word = true;
                i += 1;
                loop {
                    match chars.get(i) {
                        None => return Err("unterminated single quote".to_string()),
                        Some('\'') => {
                            i += 1;
                            break;
                        }
                        Some(&ch) => {
                            word.push((ch, true));
                            i += 1;
                        }
                    }
                }
            }
            '"' => {
                in_word = true;
                i += 1;
                loop {
                    match chars.get(i) {
                        None => return Err("unterminated double quote".to_string()),
                        Some('"') => {
                            i += 1;
                            break;
                        }
                        Some('\\')
                            if matches!(chars.get(i + 1), Some('$' | '`' | '"' | '\\' | '\n')) =>
                        {
                            word.push((chars[i + 1], true));
                            i += 2;
                        }
                        Some(&ch) => {
                            word.push((ch, !matches!(ch, '$' | '`')));
                            i += 1;
                        }
                    }
                }
            }
            _ => {
                word.push((c, false));
                in_word = true;
                i += 1;
            }
        }
    }
    flush(&mut toks, &mut word, &mut in_word);
    if !pending.is_empty() {
        return Err("here-document never ends".to_string());
    }
    Ok(toks)
}

fn literal(word: &Word) -> String {
    word.iter().map(|&(c, _)| c).collect()
}

/// Shells whose `-c` argument is a second script, parsed again.
const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ash", "ksh", "su", "script"];

fn reparses_its_argument(words: &[String]) -> bool {
    let Some((prev, earlier)) = words.split_last() else {
        return false;
    };
    let shell_flag = prev.starts_with('-') && !prev.starts_with("--") && prev.ends_with('c');
    (shell_flag
        && earlier.iter().any(|w| {
            let base = w.rsplit('/').next().unwrap_or(w);
            SHELLS.contains(&base)
        }))
        || words.first().is_some_and(|w| w == "eval")
}

/// Programs the builders start after a launcher's `--` (`kubectl run … --
/// nslookup NAME`), which read their own options again.
const LAUNCHED: &[&str] = &[
    "nslookup", "dig", "host", "getent", "wget", "curl", "ping", "nc",
];

/// Characters a POSIX shell leaves alone outside quotes.
fn inert(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(c, '-' | '_' | '%' | '.' | '/' | ':' | '+' | ',' | '=' | '@')
}

/// Programs that read options only before their first operand, so a dashed
/// value after one is an operand.
const NO_PERMUTE: &[&str] = &["echo", "printf"];

/// Where `value` landed badly in `src`, a POSIX command (or a script a shell
/// in it parses again, when `reparse`).
///
/// A [`METACHARS`] value counts from its first [`MARK`] to the `ZQY` that
/// ends it, whatever escaping a builder applied in between (JSON, URL, LDAP):
/// every character of that span must be quoted or inert. A [`DASHED`] value
/// must not open a word in a slot where the program reads options.
fn audit(src: &str, value: &str, depth: u8, reparse: bool) -> Vec<String> {
    let mut problems = Vec::new();
    let toks = match lex(src) {
        Ok(t) => t,
        Err(e) => return vec![format!("does not parse ({e})")],
    };
    let dashed = value.starts_with('-');
    let vars = detected_vars(&toks);
    let mut words: Vec<String> = Vec::new();
    // The words of each command a `$(` interrupted, with the text of the
    // substitution so far and its own `(` depth.
    let mut outer: Vec<(Vec<String>, String, u32)> = Vec::new();
    let mut seen = 0usize;
    for tok in &toks {
        let word = match tok {
            Tok::Word(word) => word,
            Tok::Op('(') if words.last().is_some_and(|w| w == "$") => {
                words.pop();
                outer.push((std::mem::take(&mut words), String::new(), 0));
                continue;
            }
            Tok::Op(c) => {
                match outer.last_mut() {
                    Some((_, _, depth)) if *c == '(' => *depth += 1,
                    Some((_, _, depth)) if *c == ')' && *depth > 0 => *depth -= 1,
                    Some(_) if *c == ')' => {
                        if let Some((before, text, _)) = outer.pop() {
                            words = before;
                            words.push(format!("$({})", detected_program(&text)));
                            continue;
                        }
                    }
                    _ => {}
                }
                words.clear();
                continue;
            }
        };
        let lit = literal(word);
        if let Some((_, text, _)) = outer.last_mut() {
            text.push(' ');
            text.push_str(&lit);
        }
        if lit.contains(MARK) {
            if reparse && depth < 3 && reparses_its_argument(&words) {
                seen += lit.matches(MARK).count();
                // The script itself is the shell's next argument: one that
                // starts with `-` is read as the shell's own options.
                if dashed && lit.starts_with('-') {
                    problems.push(format!("option-shaped script after `{}`", words.join(" ")));
                }
                problems.extend(audit(&lit, value, depth + 1, reparse));
            } else {
                problems.extend(check_word(word, &lit, value, dashed, &words, &mut seen));
            }
        }
        let program_slot = program_of(&words).is_none();
        match vars.iter().find(|(name, _)| {
            lit.strip_prefix('$')
                .map(|v| v.trim_start_matches('{').trim_end_matches('}'))
                == Some(name.as_str())
        }) {
            Some((_, program)) if program_slot => words.push(format!("$({program})")),
            _ => words.push(lit),
        }
    }
    let raw = src.matches(MARK).count();
    if seen < raw {
        problems.push(format!(
            "{} of {raw} occurrence(s) fell outside any word (comment or operator)",
            raw - seen
        ));
    }
    problems
}

/// The problems with each occurrence of `value` in one lexed word; `words`
/// are the words of the same simple command before it.
fn check_word(
    word: &Word,
    lit: &str,
    value: &str,
    dashed: bool,
    words: &[String],
    seen: &mut usize,
) -> Vec<String> {
    let mut problems = Vec::new();
    let chars: Vec<char> = lit.chars().collect();
    let mark: Vec<char> = MARK.chars().collect();
    let mut i = 0;
    while i + mark.len() <= chars.len() {
        if chars[i..i + mark.len()] != mark[..] {
            i += 1;
            continue;
        }
        *seen += 1;
        let start = if dashed && i > 0 && chars[i - 1] == '-' {
            i - 1
        } else {
            i
        };
        let end = if dashed {
            let tail: Vec<char> = value.chars().skip(1).collect();
            if chars.len() >= i + tail.len() && chars[i..i + tail.len()] == tail[..] {
                Some(i + tail.len())
            } else {
                None
            }
        } else {
            (i..chars.len().saturating_sub(2))
                .find(|&j| chars[j..j + 3] == ['Z', 'Q', 'Y'])
                .map(|j| j + 3)
        };
        let Some(end) = end else {
            problems.push(format!("split or altered: word `{lit}`"));
            i += mark.len();
            continue;
        };
        let unquoted: String = word[start..end]
            .iter()
            .filter(|&&(c, q)| !q && !inert(c))
            .map(|&(c, _)| c)
            .collect();
        if !unquoted.is_empty() {
            problems.push(format!("unquoted `{unquoted}` in word `{lit}`"));
        }
        if dashed && start == 0 && chars.first() == Some(&'-') && reads_options_here(words) {
            problems.push(format!(
                "option-shaped value in a positional slot after `{}`",
                words.join(" ")
            ));
        }
        i = end;
    }
    problems
}

/// Whether a word after `words` (the same simple command) can be read as an
/// option: not the program name or a redirection target, not after `--`, not
/// an option's value, not past the first operand of a program that stops
/// reading options there.
fn reads_options_here(words: &[String]) -> bool {
    // `--` ends the options of the program that read it, not of a program it
    // launches: in `kubectl exec p -- sh -c X`, `sh` parses its own options.
    let words = match words.iter().rposition(|w| w == "--") {
        Some(i)
            if words.get(i + 1).is_some_and(|w| {
                let base = w.rsplit('/').next().unwrap_or(w);
                SHELLS.contains(&base) || LAUNCHED.contains(&base)
            }) =>
        {
            words.get(i + 1..).unwrap_or_default()
        }
        _ => words,
    };
    let Some(program) = words.iter().find(|w| !w.contains('=')) else {
        return false;
    };
    let base = program.rsplit('/').next().unwrap_or(program);
    if NO_PERMUTE.contains(&base) && words.len() >= 2 {
        return false;
    }
    let after_end_of_options = words.iter().any(|w| w == "--" || w == "--end-of-options");
    let option_value = words
        .last()
        .is_some_and(|flag| takes_value(program_of(words), flag));
    !after_end_of_options && !option_value
}

/// The programs a builder detects at run time, `$(if command -v kubectl …)`,
/// found in the substitution's text: the first that occurs in this order.
const DETECTED: &[&str] = &[
    "compose", "crictl", "kubectl", "helm", "docker", "podman", "k3s",
];

/// The program a detection substitution prints, or `?`.
fn detected_program(text: &str) -> &'static str {
    DETECTED
        .iter()
        .find(|p| text.contains(*p))
        .copied()
        .unwrap_or("?")
}

/// Variables assigned a detection substitution, `K="$(if …)"`, with the
/// program each one holds.
fn detected_vars(toks: &[Tok]) -> Vec<(String, &'static str)> {
    toks.iter()
        .filter_map(|tok| {
            let Tok::Word(word) = tok else { return None };
            let lit = literal(word);
            let (name, value) = lit.split_once('=')?;
            let is_name = name
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            (is_name && value.starts_with("$("))
                .then(|| (name.to_string(), detected_program(value)))
        })
        .collect()
}

/// Tools the sweep calls but that send no remote command built from their
/// arguments, with why. Any other tool that stops sending commands (a new
/// validator refusing the baseline call, a hang) fails the sweep instead of
/// silently leaving it.
const UNCOVERED: &[(&str, &str)] = &[
    ("ssh_health", "reports the bridge's own pools and sessions"),
    ("ssh_history", "reads the bridge's command history"),
    (
        "ssh_net_equip_config",
        "needs a host tagged network-equipment; `commands` is raw by design",
    ),
    ("ssh_output_fetch", "reads the MCP server's output cache"),
    (
        "ssh_runbook_execute",
        "returns a plan; each step runs through `ssh_exec`",
    ),
    ("ssh_runbook_list", "lists the runbooks known locally"),
    ("ssh_runbook_validate", "checks runbook YAML locally"),
    ("ssh_status", "reports the bridge's configuration"),
];

/// Flags whose value is the next word, by program. A dashed value right
/// after one of them is that option's argument. Anything else that looks
/// like a flag (`--long=value`, a switch, an unknown pair) leaves the next
/// word open to option parsing: the list fails closed, so a new builder that
/// puts a value after a switch is caught until its flag is added here.
///
/// A program detected at run time is keyed `$(name)`. Every flag below
/// requires an argument (getopt `:`, pflag and Go `flag` non-boolean flags,
/// the programs' own parsers), so the next word is consumed whatever it
/// starts with; Ansible's argparse refuses a dashed value instead.
const TAKES_VALUE: &[(&str, &[&str])] = &[
    ("$(compose)", &["-f"]),
    (
        "$(crictl)",
        &[
            "--label",
            "--name",
            "--namespace",
            "--since",
            "--state",
            "-o",
        ],
    ),
    (
        "$(docker)",
        &[
            "--filter", "--format", "--since", "--until", "-e", "-u", "-w",
        ],
    ),
    (
        "$(helm)",
        &[
            "--api-versions",
            "--destination",
            "--filter",
            "--kube-version",
            "--password",
            "--show-only",
            "--timeout",
            "--username",
            "--version",
            "-f",
            "-l",
            "-n",
        ],
    ),
    (
        "$(kubectl)",
        &[
            "--address",
            "--as",
            "--audience",
            "--field-selector",
            "-c",
            "-l",
            "-p",
        ],
    ),
    (
        "ansible",
        &[
            "--become-user",
            "--vault-id",
            "--vault-password-file",
            "-a",
            "-i",
            "-m",
            "-u",
        ],
    ),
    ("ansible-inventory", &["--host", "-i"]),
    (
        "ansible-playbook",
        &[
            "--become-user",
            "--limit",
            "--skip-tags",
            "--tags",
            "--vault-id",
            "--vault-password-file",
            "-i",
        ],
    ),
    ("crontab", &["-u"]),
    ("curl", &["-d"]),
    ("date", &["-d"]),
    ("find", &["-name"]),
    ("git", &["-C"]),
    ("grep", &["-e"]),
    ("journalctl", &["--grep", "--since", "--until", "-g", "-u"]),
    ("ldapadd", &["-H"]),
    ("ldapmodify", &["-H"]),
    ("ldapsearch", &["-H", "-b"]),
    ("mount", &["-o", "-t"]),
    ("mysql", &["-e", "-u"]),
    ("openssl", &["-connect", "-in", "-servername"]),
    ("podman", &["--filter", "--format", "--since", "-f"]),
    ("ps", &["-u"]),
    ("psql", &["-U", "-c", "-d"]),
    ("redis-cli", &["--pattern", "-h"]),
    ("tar", &["-C", "-cf", "-tvf", "-xf"]),
    ("tcpdump", &["-i"]),
    ("terraform", &["-var"]),
    ("useradd", &["--groups", "--home-dir", "--shell"]),
    ("usermod", &["--groups", "--home", "--shell"]),
];

/// Whether `flag`, the word before a value, makes that value its argument
/// for `program`.
fn takes_value(program: Option<&str>, flag: &str) -> bool {
    if !flag.starts_with('-') || flag == "--" || flag.contains('=') {
        return false;
    }
    let Some(program) = program else {
        return false;
    };
    TAKES_VALUE
        .iter()
        .any(|(p, flags)| *p == program && flags.contains(&flag))
}

/// The program a simple command runs, past variable assignments and the
/// wrappers that run their operand (`sudo -n -u U`, `timeout 30`, `env`).
fn program_of(words: &[String]) -> Option<&str> {
    let mut i = 0;
    while let Some(w) = words.get(i) {
        let base = w.rsplit('/').next().unwrap_or(w);
        if w.contains('=') && !w.starts_with('-') {
            i += 1;
            continue;
        }
        let wrapper_values: &[&str] = match base {
            "sudo" => &["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"],
            "nice" => &["-n"],
            "ionice" => &["-c", "-n"],
            "timeout" => &["-s", "-k", "--signal", "--kill-after"],
            "env" | "nohup" | "stdbuf" => &[],
            _ => return Some(base),
        };
        i += 1;
        while let Some(o) = words.get(i) {
            if wrapper_values.contains(&o.as_str()) {
                i += 2;
            } else if o.starts_with('-') || (o.contains('=') && base == "env") {
                i += 1;
            } else {
                break;
            }
        }
        if base == "timeout" {
            i += 1;
        }
    }
    None
}

/// A value made of the characters `PowerShell` treats specially, including
/// a typographic single quote it also closes strings with.
const PS_METACHARS: &str = "ZQXa'b\u{2018}c\"d;e|f&g$(h)i`j k#l@(m)n{o}pZQY";

/// The single-quote characters a `PowerShell` verbatim string ends on.
const PS_SINGLE: &[char] = &['\'', '\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}'];
/// The double-quote characters an expandable string ends on.
const PS_DOUBLE: &[char] = &['"', '\u{201C}', '\u{201D}', '\u{201E}'];

/// Lex `src` as `PowerShell` would for this purpose: words with
/// per-character quoting, statement and pipeline operators, comments,
/// backtick escapes, verbatim `'…'` strings (a doubled quote is one literal
/// quote) and expandable `"…"` strings (where `$` and the backtick act).
#[expect(
    clippy::too_many_lines,
    reason = "one state machine; splitting it would scatter the quoting rules"
)]
fn lex_ps(src: &str) -> Result<Vec<Tok>, String> {
    let chars: Vec<char> = src.chars().collect();
    let mut toks = Vec::new();
    let mut word: Word = Vec::new();
    let mut in_word = false;
    let mut i = 0;
    let flush = |toks: &mut Vec<Tok>, word: &mut Word, in_word: &mut bool| {
        if *in_word {
            toks.push(Tok::Word(std::mem::take(word)));
            *in_word = false;
        }
    };
    while i < chars.len() {
        let c = chars[i];
        if c == '<' && chars.get(i + 1) == Some(&'#') {
            let rest: String = chars[i..].iter().collect();
            let Some(close) = rest.find("#>") else {
                return Err("unterminated block comment".to_string());
            };
            i += rest[..close].chars().count() + 2;
            continue;
        }
        if PS_SINGLE.contains(&c) {
            in_word = true;
            i += 1;
            loop {
                match chars.get(i) {
                    None => return Err("unterminated verbatim string".to_string()),
                    Some(q) if PS_SINGLE.contains(q) => {
                        if chars.get(i + 1).is_some_and(|n| PS_SINGLE.contains(n)) {
                            word.push((*q, true));
                            i += 2;
                        } else {
                            i += 1;
                            break;
                        }
                    }
                    Some(&ch) => {
                        word.push((ch, true));
                        i += 1;
                    }
                }
            }
            continue;
        }
        if PS_DOUBLE.contains(&c) {
            in_word = true;
            i += 1;
            loop {
                match chars.get(i) {
                    None => return Err("unterminated expandable string".to_string()),
                    Some(q) if PS_DOUBLE.contains(q) => {
                        if chars.get(i + 1).is_some_and(|n| PS_DOUBLE.contains(n)) {
                            word.push((*q, true));
                            i += 2;
                        } else {
                            i += 1;
                            break;
                        }
                    }
                    Some('`') => {
                        if let Some(&next) = chars.get(i + 1) {
                            word.push((next, true));
                        }
                        i += 2;
                    }
                    Some(&ch) => {
                        word.push((ch, ch != '$'));
                        i += 1;
                    }
                }
            }
            continue;
        }
        match c {
            ' ' | '\t' | '\r' => {
                flush(&mut toks, &mut word, &mut in_word);
                i += 1;
            }
            '\n' | ';' | '|' | '&' | '(' | ')' | '{' | '}' | ',' => {
                flush(&mut toks, &mut word, &mut in_word);
                toks.push(Tok::Op(c));
                i += 1;
            }
            '#' if !in_word => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '`' => {
                if let Some(&next) = chars.get(i + 1)
                    && next != '\n'
                {
                    word.push((next, true));
                    in_word = true;
                }
                i += 2;
            }
            _ => {
                word.push((c, false));
                in_word = true;
                i += 1;
            }
        }
    }
    flush(&mut toks, &mut word, &mut in_word);
    Ok(toks)
}

/// Where `value` landed badly in `src`, a `PowerShell` command (or a script
/// `Invoke-Expression` or `-Command` parses again).
fn audit_ps(src: &str, depth: u8) -> Vec<String> {
    let mut problems = Vec::new();
    let toks = match lex_ps(src) {
        Ok(t) => t,
        Err(e) => return vec![format!("does not parse ({e})")],
    };
    let mut prev: Option<String> = None;
    let mut seen = 0usize;
    for tok in &toks {
        let Tok::Word(word) = tok else {
            prev = None;
            continue;
        };
        let lit = literal(word);
        if lit.contains(MARK) {
            let reparsed = prev.as_deref().is_some_and(|p| {
                p.eq_ignore_ascii_case("Invoke-Expression")
                    || p.eq_ignore_ascii_case("iex")
                    || p.eq_ignore_ascii_case("-Command")
            });
            if depth < 3 && reparsed {
                seen += lit.matches(MARK).count();
                problems.extend(audit_ps(&lit, depth + 1));
            } else {
                let chars: Vec<char> = lit.chars().collect();
                let mut i = 0;
                while i + 3 <= chars.len() {
                    if chars[i..i + 3] != ['Z', 'Q', 'X'] {
                        i += 1;
                        continue;
                    }
                    seen += 1;
                    let Some(end) = (i..chars.len().saturating_sub(2))
                        .find(|&j| chars[j..j + 3] == ['Z', 'Q', 'Y'])
                        .map(|j| j + 3)
                    else {
                        problems.push(format!("split or altered: word `{lit}`"));
                        i += 3;
                        continue;
                    };
                    let unquoted: String = word[i..end]
                        .iter()
                        .filter(|&&(c, q)| !q && !c.is_ascii_alphanumeric())
                        .map(|&(c, _)| c)
                        .collect();
                    if !unquoted.is_empty() {
                        problems.push(format!("unquoted `{unquoted}` in word `{lit}`"));
                    }
                    i = end;
                }
            }
        }
        prev = Some(lit);
    }
    let raw = src.matches(MARK).count();
    if seen < raw {
        problems.push(format!(
            "{} of {raw} occurrence(s) fell outside any word (comment or operator)",
            raw - seen
        ));
    }
    problems
}

/// Valid values for required arguments a bare `"x"` fails validation on, so
/// the tool gets far enough to build a command for the other arguments.
const SAMPLES: &[(&str, &str)] = &[
    ("cron_expr", "0 2 * * *"),
    ("schedule", "0 2 * * *"),
    ("archive", "/srv/x.tar.gz"),
    ("snapshot_path", "/srv/snap"),
    ("k3s_bin", "/usr/local/bin/k3s"),
    ("dest", "/srv/x"),
    ("destination", "/srv/x"),
    ("path", "/srv/x"),
    ("raw_path", "/api"),
    ("probe_path", "/healthz"),
    ("url", "https://example.test/x"),
    ("webhook_url", "https://example.test/hook"),
    ("repo_url", "https://example.test/charts"),
    (
        "public_key",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample x@y",
    ),
    ("kb", "KB5034441"),
    ("size", "10Gi"),
    ("patch_type", "merge"),
    ("subcommand", "image"),
    ("kind", "container"),
    ("resource", "pods"),
    ("mapping", "8080:80"),
    ("ports", "8080:80"),
    ("version", "v1.30.0+k3s1"),
];

/// Valid values for one tool's arguments, set whether required or not (the
/// value is JSON when it parses as JSON: `true`, `4242`).
const TOOL_SAMPLES: &[(&str, &str, &str)] = &[
    ("ssh_k3s_cert_rotate", "k3s_bin", "k3s"),
    ("ssh_k3s_check_config", "k3s_bin", "k3s"),
    ("ssh_k3s_etcd_snapshot_list", "k3s_bin", "k3s"),
    ("ssh_k3s_etcd_snapshot_list", "dir", "/srv/x"),
    ("ssh_k3s_etcd_snapshot_restore", "k3s_bin", "k3s"),
    ("ssh_k3s_etcd_snapshot_save", "k3s_bin", "k3s"),
    ("ssh_k3s_etcd_snapshot_save", "dir", "/srv/x"),
    ("ssh_k3s_etcd_status", "k3s_bin", "k3s"),
    ("ssh_k3s_ctr_images", "k3s_bin", "k3s"),
    ("ssh_k3s_ctr_images", "action", "ls"),
    ("ssh_k3s_ctr_images", "tarball", "/srv/x.tar"),
    (
        "ssh_k3s_killall",
        "script_path",
        "/usr/local/bin/k3s-killall.sh",
    ),
    (
        "ssh_k3s_uninstall",
        "script_path",
        "/usr/local/bin/k3s-uninstall.sh",
    ),
    ("ssh_k3s_upgrade", "version", "v1.30.2"),
    ("ssh_podman_compose", "action", "ps"),
    ("ssh_crictl_rmi", "image", "busybox"),
    ("ssh_awx_resolve", "kind", "job_templates"),
    ("ssh_terraform_state", "subcommand", "list"),
    ("ssh_redis_cli", "command", "PING"),
    ("ssh_template_diff", "current_path", "/etc/x.conf"),
    ("ssh_template_apply", "dest", "/etc/x.conf"),
    ("ssh_template_validate", "service", "redis"),
    (
        "ssh_template_validate",
        "config_path",
        "/etc/redis/redis.conf",
    ),
    ("ssh_backup_verify", "archive", "/tmp/x.tar.gz"),
    ("ssh_reg_query", "path", "HKLM:\\SOFTWARE\\x"),
    ("ssh_reg_list", "path", "HKLM:\\SOFTWARE\\x"),
    ("ssh_reg_set", "path", "HKLM:\\SOFTWARE\\x"),
    ("ssh_reg_delete", "path", "HKLM:\\SOFTWARE\\x"),
    ("ssh_reg_export", "key", "HKLM\\SOFTWARE\\x"),
    ("ssh_reg_export", "file", "C:\\x.reg"),
    ("ssh_win_event_export", "file", "C:\\x.evtx"),
    ("ssh_helm_dependency", "subcommand", "list"),
    ("ssh_helm_diff", "subcommand", "upgrade"),
    ("ssh_helm_get", "subcommand", "values"),
    ("ssh_helm_show", "subcommand", "values"),
    ("ssh_k8s_proxy_get", "resource", "services"),
    ("ssh_k8s_proxy_get", "proxy_path", "/x"),
    ("ssh_k8s_rbac_create", "kind", "role"),
    ("ssh_k8s_secret_decode", "reveal", "true"),
    ("ssh_k8s_secret_export", "reveal", "true"),
    ("ssh_k8s_top", "resource_type", "pods"),
    ("ssh_k8s_watch", "resource", "pods"),
    ("ssh_k8s_volume_expand", "size", "1Gi"),
    ("ssh_traefik_introspect", "api_path", "/x"),
    ("ssh_capacity_predict", "resource", "cpu"),
    ("ssh_file_chmod", "mode", "u+x"),
    ("ssh_win_update_install", "kb", "KB5034441"),
    ("ssh_vault_write", "data", r#"["k=x"]"#),
    ("ssh_process_kill", "pid", "4242"),
];

/// The value each property of `schema` gets for one sweep call: `hostile`
/// for `key` (none for a baseline call), a minimal valid value for the rest.
fn args_with(tool: &str, schema: &Value, key: Option<(&str, &Value)>, posix: bool) -> Value {
    let mut args = minimal_value(schema);
    if let Some(obj) = args.as_object_mut() {
        if schema["properties"].get("host").is_some() {
            obj.insert("host".to_string(), json!("target"));
        }
        if schema["properties"]["hosts"]["type"] == "array" {
            obj.insert("hosts".to_string(), json!(["target"]));
        }
        for (name, sample) in SAMPLES.iter().filter(|_| posix) {
            if obj.contains_key(*name) && obj[*name].is_string() {
                obj.insert((*name).to_string(), json!(sample));
            }
        }
        for (_, name, sample) in TOOL_SAMPLES.iter().filter(|(t, ..)| *t == tool) {
            if schema["properties"].get(*name).is_some() {
                let value = serde_json::from_str(sample).unwrap_or_else(|_| json!(sample));
                obj.insert((*name).to_string(), value);
            }
        }
        if let Some((key, hostile)) = key {
            obj.insert(key.to_string(), hostile.clone());
        }
    }
    args
}

/// How to put `value` into `prop`, or `None` when the property takes no text.
fn hostile_for(prop: &Value, value: &str) -> Option<Value> {
    if prop.get("enum").is_some() {
        return None;
    }
    let ty = &prop["type"];
    let is = |t: &str| ty == t || ty.as_array().is_some_and(|a| a.iter().any(|x| x == t));
    if is("string") {
        Some(json!(value))
    } else if is("array")
        && (prop["items"]["type"] == "string")
        && prop["items"].get("enum").is_none()
    {
        Some(json!([value]))
    } else if is("object") && prop["additionalProperties"]["type"] == "string" {
        Some(json!({ "k": value }))
    } else {
        None
    }
}

/// A context whose host `target` (also `awx.ssh_host`) has `os_type` and the
/// `extra` YAML-level fields, behind a mock executor that records commands.
fn sweep_context(os_type: &str, extra: &str) -> ToolContext {
    let base =
        crate::mcp::tool_handlers::utils::guard_test_support::context_with_target(os_type, extra);
    let mut config = (*base.config).clone();
    config.security.mode = crate::config::SecurityMode::Permissive;
    config.security.require_elicitation_on_destructive = false;
    // The blacklist is a policy, not quoting: without it, the tools whose
    // default command it refuses (`systemctl stop`, `dd if=`) build too.
    config.security.blacklist.clear();
    config.awx = Some(crate::config::AwxConfig {
        ssh_host: "target".to_string(),
        url: "https://awx.test".to_string(),
        token: crate::config::RedactedSecret::from("awx-token"),
        api_timeout: 30,
        verify_ssl: true,
    });
    crate::ports::mock::create_test_context_with_config_and_mock_executor(
        config,
        crate::ssh::CommandOutput {
            exit_code: 0,
            stdout: "{}".to_string(),
            stderr: String::new(),
            duration_ms: 1,
        },
    )
}

/// What one call produced: the commands the mock received, or the text of
/// the result or error when it sent none.
async fn call(
    registry: &crate::mcp::registry::ToolRegistry,
    ctx: &ToolContext,
    name: &str,
    args: Value,
) -> Result<(Vec<String>, String), ()> {
    let before = ctx.connection_pool.mock_calls().len();
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        registry.execute(name, Some(args), ctx),
    )
    .await
    .map_err(|_| ())?;
    let text = match outcome {
        Ok(r) => r
            .content
            .first()
            .map(|c| match c {
                crate::mcp::protocol::ToolContent::Text { text } => {
                    text.chars().take(140).collect()
                }
                _ => "non-text".to_string(),
            })
            .unwrap_or_default(),
        Err(e) => e.to_string().chars().take(140).collect(),
    };
    let commands = ctx.connection_pool.mock_calls()[before..]
        .iter()
        .map(|(c, _)| c.clone())
        .collect();
    Ok((commands, text))
}

#[tokio::test(flavor = "multi_thread")]
#[expect(
    clippy::too_many_lines,
    reason = "the sweep and its report read best as one walk over the registry"
)]
async fn every_tool_keeps_each_argument_one_quoted_word() {
    let posix = sweep_context("linux", "");
    let pwsh = sweep_context("windows", r#","shell":"powershell""#);
    let registry = crate::mcp::registry::create_all_enabled_registry();
    let mut tools = registry.list_tools();
    tools.sort_by(|a, b| a.name.cmp(&b.name));

    let mut problems: Vec<String> = Vec::new();
    let mut not_covered: Vec<String> = Vec::new();
    let mut timed_out: Vec<String> = Vec::new();
    let mut swept = 0usize;
    let mut covered = 0usize;
    let mut windows_tools = 0usize;

    for tool in &tools {
        let name = tool.name.as_str();
        if SKIPPED_TOOLS.contains(&name) || SKIPPED_PREFIXES.iter().any(|p| name.starts_with(p)) {
            continue;
        }
        let schema = &tool.input_schema;
        let Some(props) = schema["properties"].as_object() else {
            continue;
        };
        // A baseline call decides the target: Windows tools refuse a Linux host.
        let Ok((mut sent, baseline)) =
            call(&registry, &posix, name, args_with(name, schema, None, true)).await
        else {
            timed_out.push(format!("{name} (baseline)"));
            continue;
        };
        let windows = baseline.contains("only available on Windows hosts");
        let (ctx, values): (&ToolContext, &[&str]) = if windows {
            windows_tools += 1;
            sent = call(&registry, &pwsh, name, args_with(name, schema, None, false))
                .await
                .map(|(c, _)| c)
                .unwrap_or_default();
            (&pwsh, &[PS_METACHARS])
        } else {
            (&posix, &[METACHARS, DASHED])
        };
        let mut ran_any = !sent.is_empty();
        let mut refusals: Vec<String> = Vec::new();
        for (key, prop) in props {
            if SKIPPED_ARGS.contains(&key.as_str()) {
                continue;
            }
            for &value in values {
                let Some(hostile) = hostile_for(prop, value) else {
                    continue;
                };
                swept += 1;
                let Ok((commands, text)) = call(
                    &registry,
                    ctx,
                    name,
                    args_with(name, schema, Some((key, &hostile)), !windows),
                )
                .await
                else {
                    timed_out.push(format!("{name}.{key}"));
                    continue;
                };
                if commands.is_empty() {
                    refusals.push(format!("{key}: {text}"));
                }
                for command in &commands {
                    ran_any = true;
                    let raw = raw_kind(name, key);
                    if !command.contains(MARK) || raw == Some(Raw::Whole) {
                        continue;
                    }
                    if raw == Some(Raw::Options) && value == DASHED {
                        continue;
                    }
                    let found = if windows {
                        audit_ps(command, 0)
                    } else {
                        audit(command, value, 0, raw.is_none())
                    };
                    let tag = if value == DASHED {
                        "dash"
                    } else if windows {
                        "pwsh"
                    } else {
                        "meta"
                    };
                    for p in found {
                        problems.push(format!("{name}.{key} [{tag}]: {p}\n    command: {command}"));
                    }
                }
            }
        }
        if ran_any {
            covered += 1;
        } else {
            let why = if refusals.is_empty() {
                format!("baseline: {baseline}")
            } else {
                format!("baseline: {baseline} || {}", refusals.join(" | "))
            };
            not_covered.push(format!("{name}: {why}"));
        }
    }

    let mut report = String::new();
    let _ = writeln!(
        report,
        "swept {swept} (tool, argument, value) calls; {covered} of {} tools sent commands \
         ({windows_tools} Windows tools against a PowerShell host)",
        tools.len()
    );
    let _ = writeln!(report, "{} tools sent no command:", not_covered.len());
    for t in &not_covered {
        let _ = writeln!(report, "  . {t}");
    }
    let _ = writeln!(report, "timed out: {}", timed_out.join(", "));
    let _ = writeln!(report, "{} problem(s):", problems.len());
    for p in &problems {
        let _ = writeln!(report, "- {p}");
    }
    if std::env::var_os("SWEEP_REPORT").is_some() {
        println!("{report}");
    }
    assert!(problems.is_empty(), "{report}");
    assert!(timed_out.is_empty(), "{report}");
    let mut uncovered: Vec<&str> = not_covered
        .iter()
        .map(|t| t.split(':').next().unwrap_or(t))
        .collect();
    uncovered.sort_unstable();
    let mut expected: Vec<&str> = UNCOVERED.iter().map(|(name, _)| *name).collect();
    expected.sort_unstable();
    assert_eq!(
        uncovered, expected,
        "the tools that send no command changed: cover them, or list them in UNCOVERED\n{report}"
    );
}

mod lexer_tests {
    use super::*;
    use crate::mcp::tool_handlers::utils::shell_escape;

    /// No problem found in `cmd` for `value`.
    fn clean(cmd: &str, value: &str) {
        assert_eq!(audit(cmd, value, 0, true), Vec::<String>::new(), "{cmd}");
    }

    /// At least one problem found in `cmd` for `value`.
    fn flagged(cmd: &str, value: &str) {
        assert_ne!(audit(cmd, value, 0, true).len(), 0, "not flagged: {cmd}");
    }

    #[test]
    fn a_single_quoted_value_is_safe() {
        clean(
            &format!("git -C {} status", shell_escape(METACHARS)),
            METACHARS,
        );
    }

    #[test]
    fn a_raw_value_is_caught() {
        flagged(&format!("ldapsearch -b x {METACHARS}"), METACHARS);
    }

    #[test]
    fn a_doubly_quoted_value_is_caught() {
        flagged(
            &format!("ansible all -a 'filter={}'", shell_escape(METACHARS)),
            METACHARS,
        );
    }

    #[test]
    fn a_value_inside_sh_c_is_checked_again() {
        let inner = format!("echo {}", shell_escape(METACHARS));
        clean(&format!("sh -c {}", shell_escape(&inner)), METACHARS);
        flagged(
            &format!("sh -c {}", shell_escape(&format!("echo {METACHARS}"))),
            METACHARS,
        );
    }

    #[test]
    fn a_dashed_value_in_a_positional_slot_is_caught() {
        let q = shell_escape(DASHED);
        flagged(&format!("find {q} -type f"), DASHED);
        clean(&format!("grep -e {q} f"), DASHED);
        clean(&format!("git log -- {q}"), DASHED);
    }

    /// A dashed value after a flag passes only when that program's flag is
    /// known to take the next word as its argument.
    #[test]
    fn a_dashed_value_after_a_switch_is_caught() {
        let q = shell_escape(DASHED);
        clean(&format!("git -C {q} status"), DASHED);
        flagged(&format!("useradd -m {q}"), DASHED);
        flagged(&format!("git log --format=x {q}"), DASHED);
        // `-n` takes a value for helm, not for diff.
        flagged(&format!("diff -n {q} b"), DASHED);
        let helm = "$(if command -v helm >/dev/null 2>&1; then echo helm; else echo false; fi)";
        clean(&format!("{helm} diff upgrade -n {q} r c"), DASHED);
        flagged(&format!("{helm} diff upgrade {q} c"), DASHED);
    }

    /// `--` ends the launcher's options only: the shell it starts reads its
    /// own again.
    #[test]
    fn a_dashed_value_after_a_launched_shell_is_caught() {
        let q = shell_escape(DASHED);
        flagged(&format!("kubectl exec p -- sh -c {q}"), DASHED);
        flagged(&format!("kubectl run x -- nslookup {q}"), DASHED);
        clean(&format!("kubectl exec p -- sh -c -- {q}"), DASHED);
        clean(&format!("git log -- {q}"), DASHED);
        clean(&format!("tar czf a.tgz -- {q} b"), DASHED);
    }

    /// A program a builder detects at run time is resolved through the
    /// substitution, or the variable holding it, past wrappers.
    #[test]
    fn a_detected_program_is_resolved() {
        let q = shell_escape(DASHED);
        let detect = "\"$(if command -v kubectl >/dev/null 2>&1; then echo kubectl; fi)\"";
        clean(
            &format!("K={detect}; timeout 60 $K get pods -l {q}"),
            DASHED,
        );
        flagged(
            &format!("K={detect}; timeout 60 $K get pods -w {q}"),
            DASHED,
        );
        flagged(&format!("K={detect}; $K get {q}"), DASHED);
    }

    #[test]
    fn a_quoted_here_document_body_is_literal() {
        clean(&format!("cat <<'EOF'\n{METACHARS}\nEOF\n"), METACHARS);
    }

    #[test]
    fn a_powershell_quoted_value_is_safe() {
        let q = crate::domain::use_cases::shell::escape(
            PS_METACHARS,
            crate::config::ShellType::PowerShell,
        );
        assert_eq!(
            audit_ps(&format!("Get-Service -Name {q}"), 0),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_powershell_value_quoted_for_posix_is_caught() {
        let q = shell_escape(PS_METACHARS);
        assert_ne!(audit_ps(&format!("Get-Service -Name {q}"), 0).len(), 0);
    }

    #[test]
    fn a_dashed_program_name_or_redirection_target_is_not_an_option() {
        let q = shell_escape(DASHED);
        clean(&format!("export LC_ALL=C; {q} ps"), DASHED);
        clean(&format!("mysqldump db > {q}"), DASHED);
        clean(&format!("echo 'rendered to' {q}"), DASHED);
        flagged(&format!("echo {q}"), DASHED);
        flagged(&format!("sudo {q} kubectl"), DASHED);
    }

    #[test]
    fn an_encoded_value_counts_when_its_word_is_quoted() {
        let url = format!("https://h/x?q={}", "ZQXa%27b%22c%3Bd%20ZQY");
        clean(&format!("curl {}", shell_escape(&url)), METACHARS);
        flagged(&format!("curl https://h/x?q={METACHARS}"), METACHARS);
    }

    #[test]
    fn an_inner_script_must_still_be_one_word() {
        let inner = format!("sh -c {}", shell_escape(METACHARS));
        assert_eq!(audit(&inner, METACHARS, 0, false), Vec::<String>::new());
        let spliced = format!("sh -c '{METACHARS}'");
        assert_ne!(audit(&spliced, METACHARS, 0, false).len(), 0);
    }

    #[test]
    fn a_value_in_a_comment_is_caught() {
        flagged(&format!("echo x # {}", shell_escape(METACHARS)), METACHARS);
    }
}
