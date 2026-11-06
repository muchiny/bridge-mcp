#![no_main]

use std::collections::HashMap;
use std::sync::Once;

use bridge_mcp::AnsibleCommandBuilder;
use bridge_mcp_fuzz::{
    Guard, assert_arrives_as_text, shell_words, split_guards, take_guard, take_word,
};
use libfuzzer_sys::fuzz_target;

// This target used to assert only the PROGRAM NAME: `assert!(cmd.contains(
// "--list"))`. That is a string the builder writes itself, in every branch,
// whatever the caller passed — so NO INPUT COULD EVER FAIL IT. A builder that
// pastes `data` into the command line in bare does not panic and does not drop
// the program name; it produces a dangerous command and the target stays
// green. An echo, not a property.
//
// What it asserts now: whatever the builder PRODUCED arrives in the command as
// TEXT — inside one literal run, having contributed no shell syntax. (The
// builders refuse nothing, see the end of this header; the fuzzer is looking
// for values that get THROUGH.)
//
// `assert_arrives_as_text` rather than `assert_survives_as_one_word`: these
// builders emit pipelines and `&&` chains of their own, and an oracle that
// refuses every operator would be red on healthy code. It is `contains` on the
// literal run rather than equality because a value legitimately lands inside a
// larger word (`--filter=name=VALUE`); an operator still splits the run either
// way, which is what the assertion is for.
//
// SINCE 6.0.0 (GHSA-vcgr-hw4v-9r68) a command that names a vault password file
// (`vault_password_file`, or the source of a `vault_id`) does not START with
// the program any more. It starts with one fail-closed guard per file:
//
//   [cd -- DIR && ]
//   if [ -f P ] && [ -n "$(find -L P -prune ! -perm -100 ! -perm -010 ! -perm -001 -print 2>/dev/null)" ];
//     then :; else echo MESSAGE >&2; exit 2; fi && ...
//   [ANSIBLE_STDOUT_CALLBACK=CB ][ANSIBLE_INVENTORY_ENABLED=... ]ansible... ARGS
//
// The old `starts_with("ansible ")` check was therefore false on every input,
// the empty one included (issue #276), and everything after it was never
// reached.
//
// The guard cannot go through `shell_shape` (so not through
// `assert_arrives_as_text` either): it nests a single-quoted path inside
// `"$(...)"`, and `shell_shape` reads the double-quoted region as a flat string.
// A path holding a `"` closes that region early in the scanner while the real
// shell, which parses `$( )` afresh, is perfectly fine; the scan then fails on
// healthy code. So the command is taken apart in three:
//
// * the guards are read by `take_guard` (and `split_guards`, `take_word`) from
//   `bridge_mcp_fuzz`, where they have unit tests of their own: a reader that
//   knows the guard's fixed text and reads each of its three quoted words (the
//   path tested, the path given to `find`, the message) as the shell would.
//   What it recovers is compared with the path the caller passed: the path
//   arrives as TEXT inside the guard, and the fixed text pins that a refused
//   file ends the shell with status 2 and that the guard is chained to what
//   follows with `&&`;
// * what is left after the guards is the real command, and it IS a plain word
//   list: `shell_words` must read it, and every flag must carry the caller's
//   value as its own word (a pair `flag value`, `--vault-password-file` and
//   `--vault-id` included);
// * `assert_arrives_as_text` runs on that remainder, as before.
//
// Every property is "whatever the builder produced for THIS input". The
// builders refuse nothing (validation is a separate step), so there is no
// "accepted" filter to apply, and no over-refusal direction to assert on fuzz
// data.
//
// The vault rules (`prompt` sources, `LABEL@SOURCE`, `~/`, the `./` prefix, one
// guard per distinct file) are written out here (`vault_id_source`,
// `expected_sources`, `assert_guards`), not called from the product: an oracle
// that asks the builder what the builder should do cannot disagree with it.
// Not all of them are independent of the product, though: the split of
// `vault_id_source` on the first `@` is a VERBATIM COPY of the product's
// private helper of the same name (both follow Ansible's `CLI.split_vault_id`),
// so a bug in that split reproduced on both sides cancels out here. What pins
// it is `fixed_vault_cases` (`a@b@c`, `x@y@prompt`, `prod@prompt`, ...), whose
// expected answers are read by a human, not derived from the code. The `~/`,
// `./`, dedup and message rules are restated from the documentation.
// Those branches are rare in fuzz data (every field gets the same `data`, so
// `prompt` or `x@prompt` must be invented byte by byte), so they are also run
// on FIXED hand-picked inputs (`fixed_vault_cases`), and one fixed run with a
// DISTINCT value per field pins which flag carries which value and that no word
// is added (`check_distinct_values`); the fuzzed all-`data` runs cannot tell two
// flags apart.
//
// Run with the dictionary or this explores very little:
// `cargo +nightly fuzz run fuzz_ansible_command_builder -- -dict=fuzz/dicts/shell.dict`

/// The file a `--vault-id` value reads its password from, or `None` for a
/// prompt: the part after the first `@` (Ansible's `CLI.split_vault_id`), or
/// the whole value without one. The split is a verbatim copy of the product's
/// private helper (this does not call it, and cannot: it is not exported), so
/// it is pinned by `fixed_vault_cases` and not by disagreement with the
/// builder; the two prompt names are written out here.
fn vault_id_source(vault_id: &str) -> Option<&str> {
    let source = vault_id.split_once('@').map_or(vault_id, |(_, s)| s);
    (source != "prompt" && source != "prompt_ask_vault_pass").then_some(source)
}

/// The files that must be guarded, in command-line order and without
/// duplicates: `--vault-password-file` first, then the source of `--vault-id`.
fn expected_sources<'a>(vpf: Option<&'a str>, vid: Option<&'a str>) -> Vec<&'a str> {
    let mut sources: Vec<&str> = Vec::new();
    for source in vpf.into_iter().chain(vid.and_then(vault_id_source)) {
        if !sources.contains(&source) {
            sources.push(source);
        }
    }
    sources
}

/// Every file Ansible would be given has exactly one guard, in order, and each
/// guard names that file as text in all three of its words.
fn assert_guards(guards: &[Guard], sources: &[&str], cmd: &str, context: &str) {
    assert_eq!(
        guards.len(),
        sources.len(),
        "{context}: expected one guard per vault file {sources:?}, got {}.\n  built: {cmd:?}",
        guards.len()
    );
    for (guard, &source) in guards.iter().zip(sources) {
        // A leading `~/` is left to the shell as `"$HOME"/`; anything else is
        // the caller's text unchanged.
        let path = match source.strip_prefix("~/") {
            Some(rest) => format!("$HOME/{rest}"),
            None => source.to_string(),
        };
        // `find` reads a first operand starting with one of these as part of
        // its expression, so the guard gives it `./PATH` instead.
        let found = if source.starts_with(['!', '(', ')', ',']) {
            format!("./{path}")
        } else {
            path.clone()
        };
        assert_eq!(
            guard.path, path,
            "{context}: the tested path is not the vault file {source:?}.\n  built: {cmd:?}"
        );
        assert_eq!(
            guard.found, found,
            "{context}: `find` does not get the vault file {source:?} as one operand.\n  built: {cmd:?}"
        );
        assert!(
            guard
                .message
                .contains(&format!("vault password file {source} must be"))
                && guard.message.contains("execute permission"),
            "{context}: the refusal message does not name {source:?}: {:?}",
            guard.message
        );
    }
}

/// The words of the command that follows the guards, with a cursor.
struct Words<'a> {
    words: Vec<String>,
    at: usize,
    cmd: &'a str,
    context: &'a str,
}

impl<'a> Words<'a> {
    /// The command that is left after the guards is a plain word list.
    fn new(rest: &str, cmd: &'a str, context: &'a str) -> Self {
        let Some(words) = shell_words(rest) else {
            panic!(
                "{context}: the command after the guards is not a plain word list, so a \
                 caller value became shell syntax.\n  built: {cmd:?}"
            );
        };
        Self {
            words,
            at: 0,
            cmd,
            context,
        }
    }

    /// The next word is exactly `expected`.
    fn next_is(&mut self, expected: &str) {
        let got = self.words.get(self.at).map(String::as_str);
        assert_eq!(
            got,
            Some(expected),
            "{}: word {} of {:?} (words {:?})",
            self.context,
            self.at,
            self.cmd,
            self.words
        );
        self.at += 1;
    }

    /// The next word restricts the inventory plugins to the ones that parse the
    /// source as data: every plugin it enables is `host_list`, `yaml`, `ini` or
    /// `toml`, so `script` (which RUNS the source) is off, and so is anything
    /// else not vetted.
    fn next_is_inventory_env(&mut self) {
        const DATA_PLUGINS: [&str; 4] = ["host_list", "yaml", "ini", "toml"];
        let got = self.words.get(self.at).map(String::as_str);
        let plugins = got.and_then(|w| w.strip_prefix("ANSIBLE_INVENTORY_ENABLED="));
        assert!(
            matches!(plugins, Some(list) if list.split(',').all(|p| DATA_PLUGINS.contains(&p))),
            "{}: expected an ANSIBLE_INVENTORY_ENABLED assignment naming only data \
             inventory plugins (no `script`) at word {}, got {:?} in {:?}",
            self.context,
            self.at,
            got,
            self.cmd
        );
        self.at += 1;
    }

    /// Every word left is exactly `expected`, in order, and nothing else.
    fn rest_is(&mut self, expected: &[&str]) {
        let got: Vec<&str> = self
            .words
            .get(self.at..)
            .unwrap_or_default()
            .iter()
            .map(String::as_str)
            .collect();
        assert_eq!(
            got, expected,
            "{}: the words after word {} are not the expected ones, in {:?}",
            self.context, self.at, self.cmd
        );
        self.at = self.words.len();
    }

    /// Nothing is left after the words consumed so far.
    fn done(&self) {
        assert_eq!(
            self.at,
            self.words.len(),
            "{}: unexpected words after the program line: {:?} in {:?}",
            self.context,
            self.words,
            self.cmd
        );
    }

    /// `flag` is a word of its own.
    fn has_flag(&self, flag: &str) {
        assert!(
            self.words.iter().any(|w| w == flag),
            "{}: missing {flag:?} in {:?} (words {:?})",
            self.context,
            self.cmd,
            self.words
        );
    }

    /// `flag` is directly followed by `value` as ONE word: the caller's value
    /// reached the option it was given for, whole.
    fn has_pair(&self, flag: &str, value: &str) {
        assert!(
            self.words.windows(2).any(|w| w[0] == flag && w[1] == value),
            "{}: {flag:?} is not followed by {value:?} as one word in {:?} (words {:?})",
            self.context,
            self.cmd,
            self.words
        );
    }
}

/// `build_playbook_command` with every field set to `data`, for one choice of
/// the two vault arguments.
fn check_playbook(data: &str, vpf: Option<&str>, vid: Option<&str>) {
    let context = &format!("playbook (vault_password_file {vpf:?}, vault_id {vid:?})");
    let mut extra_vars = HashMap::new();
    extra_vars.insert(data.to_string(), data.to_string());
    let cmd = AnsibleCommandBuilder::build_playbook_command(
        data,              // playbook
        Some(data),        // inventory
        Some(data),        // limit
        Some(data),        // tags
        Some(data),        // skip_tags
        Some(&extra_vars), // extra_vars
        true,              // check
        true,              // diff
        Some(4),           // verbose
        Some(10),          // forks
        true,              // use_become
        Some(data),        // become_user
        Some(data),        // working_dir
        Some(data),        // callback
        vpf,               // vault_password_file
        vid,               // vault_id
    );

    // `cd -- DIR && ` comes first, so the guards test the path from the
    // directory Ansible resolves it from.
    let Some(rest) = cmd.strip_prefix("cd -- ") else {
        panic!("{context}: the command does not start with `cd -- `: {cmd:?}");
    };
    let Some((dir, rest)) = take_word(rest) else {
        panic!("{context}: the working directory is not one quoted word: {cmd:?}");
    };
    assert_eq!(
        dir, data,
        "{context}: the working directory changed: {cmd:?}"
    );
    let Some(rest) = rest.strip_prefix(" && ") else {
        panic!("{context}: `cd` is not chained to what follows by '&&': {cmd:?}");
    };

    let (guards, rest) = split_guards(rest, context);
    assert_guards(&guards, &expected_sources(vpf, vid), &cmd, context);
    assert_arrives_as_text(rest, data, context);

    // The assignments belong to `ansible-playbook`, not to `cd` or a guard.
    let mut words = Words::new(rest, &cmd, context);
    words.next_is(&format!("ANSIBLE_STDOUT_CALLBACK={data}"));
    words.next_is_inventory_env();
    words.next_is("ansible-playbook");
    words.next_is(data);
    for flag in ["-i", "--limit", "--tags", "--skip-tags", "--become-user"] {
        words.has_pair(flag, data);
    }
    for flag in ["--check", "--diff", "-vvvv", "-b"] {
        words.has_flag(flag);
    }
    words.has_pair("-f", "10");
    // The extra vars are ONE JSON document, JSON-escaped rather than escaped
    // for the shell, so they are read back as JSON and compared whole.
    assert!(
        words.words.windows(2).any(|w| {
            w[0] == "-e"
                && serde_json::from_str::<HashMap<String, String>>(&w[1])
                    .is_ok_and(|vars| vars == extra_vars)
        }),
        "{context}: -e is not followed by the extra vars as one JSON word: {cmd:?}"
    );
    if let Some(vpf) = vpf {
        words.has_pair("--vault-password-file", vpf);
    }
    if let Some(vid) = vid {
        words.has_pair("--vault-id", vid);
    }
}

/// `build_adhoc_command` with every field set to `data`, for one choice of the
/// two vault arguments.
fn check_adhoc(data: &str, vpf: Option<&str>, vid: Option<&str>) {
    let context = &format!("adhoc (vault_password_file {vpf:?}, vault_id {vid:?})");
    let cmd = AnsibleCommandBuilder::build_adhoc_command(
        data,       // pattern
        data,       // module
        Some(data), // args
        Some(data), // inventory
        true,       // use_become
        Some(data), // become_user
        Some(data), // user
        Some(5),    // forks
        Some(2),    // verbose
        true,       // check
        vpf,        // vault_password_file
        vid,        // vault_id
    );

    // The guards come before anything else, the program included.
    let (guards, rest) = split_guards(&cmd, context);
    assert_guards(&guards, &expected_sources(vpf, vid), &cmd, context);
    assert_arrives_as_text(rest, data, context);

    let mut words = Words::new(rest, &cmd, context);
    words.next_is_inventory_env();
    words.next_is("ansible");
    words.next_is(data);
    words.next_is("-m");
    words.next_is(data);
    for flag in ["-a", "-i", "--become-user", "-u"] {
        words.has_pair(flag, data);
    }
    for flag in ["-b", "-vv", "-C"] {
        words.has_flag(flag);
    }
    words.has_pair("-f", "5");
    if let Some(vpf) = vpf {
        words.has_pair("--vault-password-file", vpf);
    }
    if let Some(vid) = vid {
        words.has_pair("--vault-id", vid);
    }
}

/// `vault_precheck`, the foreground form of the guards for a command that is
/// launched in the background: `( [cd -- DIR && ]GUARD [&& GUARD...] ) || exit
/// $?; `, or nothing when no file is to be guarded.
fn check_precheck(dir: Option<&str>, vpf: Option<&str>, vid: Option<&str>) {
    let context = &format!(
        "vault_precheck (working_dir {dir:?}, vault_password_file {vpf:?}, vault_id {vid:?})"
    );
    let pre = AnsibleCommandBuilder::vault_precheck(dir, vpf, vid);
    let sources = expected_sources(vpf, vid);
    if sources.is_empty() {
        assert_eq!(pre, "", "{context}: nothing to guard, yet got a prefix");
        return;
    }
    let Some(mut rest) = pre.strip_prefix("( ") else {
        panic!("{context}: the guards are not in a subshell: {pre:?}");
    };
    if let Some(dir) = dir {
        let Some(after) = rest.strip_prefix("cd -- ") else {
            panic!("{context}: the subshell does not start with `cd -- `: {pre:?}");
        };
        let Some((got, after)) = take_word(after) else {
            panic!("{context}: the working directory is not one quoted word: {pre:?}");
        };
        assert_eq!(
            got, dir,
            "{context}: the working directory changed: {pre:?}"
        );
        let Some(after) = after.strip_prefix(" && ") else {
            panic!("{context}: `cd` is not chained to the guards by '&&': {pre:?}");
        };
        rest = after;
    }
    let mut guards = Vec::new();
    loop {
        let Some((guard, after)) = take_guard(rest) else {
            panic!("{context}: a vault guard does not have the fail-closed shape: {pre:?}");
        };
        guards.push(guard);
        match after.strip_prefix(" && ") {
            Some(next) => rest = next,
            None => {
                rest = after;
                break;
            }
        }
    }
    // A refused file ends the CALLER with the status of the subshell (2).
    assert_eq!(
        rest, " ) || exit $?; ",
        "{context}: the subshell is not followed by `|| exit $?`: {pre:?}"
    );
    assert_guards(&guards, &sources, &pre, context);
}

/// `build_facts_command` with every field set to `data`: one fixed word list.
fn check_facts(data: &str) {
    let context = "facts";
    let cmd = AnsibleCommandBuilder::build_facts_command(
        data,       // pattern
        Some(data), // filter
        Some(data), // inventory
        true,       // use_become
        Some(data), // become_user
    );
    assert_arrives_as_text(&cmd, data, context);
    let mut words = Words::new(&cmd, &cmd, context);
    words.next_is_inventory_env();
    words.next_is("ansible");
    words.next_is(data);
    words.next_is("-m");
    words.next_is("setup");
    words.next_is("-a");
    // The filter is ONE word with its `filter=` key, so it cannot become a
    // second `key=value` of the module arguments.
    words.next_is(&format!("filter={data}"));
    words.next_is("-i");
    words.next_is(data);
    words.next_is("-b");
    words.next_is("--become-user");
    words.next_is(data);
    words.done();
}

/// Fixed, hand-picked vault arguments. Each one reaches a branch that fuzz data
/// reaches only by luck, and each is a pair a human can read the answer of.
/// Every property is checked against the oracle's own restatement of the rule
/// (`expected_sources` and `assert_guards`), so a regression in the product is
/// a failure on THESE inputs, deterministically, on every run.
fn fixed_vault_cases() {
    let cases: &[(Option<&str>, Option<&str>)] = &[
        // No file at all.
        (None, None),
        // Two distinct files: two guards, `--vault-password-file` first.
        (
            Some("/etc/ansible/pass"),
            Some("prod@/etc/ansible/prod-pass"),
        ),
        (Some("/p"), Some("a@/q")),
        (Some("a"), Some("l@b")),
        // The same file twice: one guard.
        (Some("/p"), Some("/p")),
        (Some("/p"), Some("a@/p")),
        (Some("a"), Some("l@a")),
        // A prompt is no file: no guard for it, and `--vault-password-file`
        // keeps its own.
        (Some("/etc/ansible/pass"), Some("prompt")),
        (None, Some("prompt")),
        (None, Some("prompt_ask_vault_pass")),
        (None, Some("prod@prompt")),
        (None, Some("prod@prompt_ask_vault_pass")),
        // The split is on the FIRST `@`: what is left is a file.
        (None, Some("a@b@c")),
        (None, Some("x@y@prompt")),
        // A leading `~/` is left to the shell; `~user/` is a plain name.
        (Some("~/v"), None),
        (Some("~/.vault pass"), None),
        (None, Some("id@~/w")),
        (Some("~user/x"), None),
        // `find` would read these as part of its expression: `./` in front.
        (Some("!x"), None),
        (Some("(x"), Some(")y")),
        (None, Some("v@,x")),
        // Quoting, and the empty file.
        (Some("it's a $(id) file"), None),
        (Some(""), None),
        (None, Some("")),
    ];
    for &(vpf, vid) in cases {
        check_playbook("d", vpf, vid);
        check_adhoc("d", vpf, vid);
        check_precheck(Some("d"), vpf, vid);
        check_precheck(None, vpf, vid);
    }
}

/// One run per builder with a DISTINCT value in every field, and the EXACT word
/// list expected. The fuzzed runs give every field the same `data`, so they
/// cannot see two flags swapped or a word added; this one can, and since the
/// input is fixed it cannot be a false positive.
fn check_distinct_values() {
    let context = "distinct values (playbook)";
    let vars = HashMap::from([("k".to_string(), "v".to_string())]);
    let cmd = AnsibleCommandBuilder::build_playbook_command(
        "pb.yml",
        Some("inv"),
        Some("lim"),
        Some("tg"),
        Some("skt"),
        Some(&vars),
        true,
        true,
        Some(2),
        Some(3),
        true,
        Some("bu"),
        Some("/w"),
        Some("cb"),
        Some("/p"),
        Some("l@/q"),
    );
    let Some(rest) = cmd.strip_prefix("cd -- '/w' && ") else {
        panic!("{context}: the command does not start with `cd -- '/w' && `: {cmd:?}");
    };
    let (guards, rest) = split_guards(rest, context);
    assert_guards(&guards, &["/p", "/q"], &cmd, context);
    let mut words = Words::new(rest, &cmd, context);
    words.next_is("ANSIBLE_STDOUT_CALLBACK=cb");
    words.next_is_inventory_env();
    words.rest_is(&[
        "ansible-playbook",
        "pb.yml",
        "-i",
        "inv",
        "--limit",
        "lim",
        "--tags",
        "tg",
        "--skip-tags",
        "skt",
        "-e",
        r#"{"k":"v"}"#,
        "--check",
        "--diff",
        "-vv",
        "-f",
        "3",
        "-b",
        "--become-user",
        "bu",
        "--vault-password-file",
        "/p",
        "--vault-id",
        "l@/q",
    ]);

    let context = "distinct values (adhoc)";
    let cmd = AnsibleCommandBuilder::build_adhoc_command(
        "pat",
        "mod",
        Some("ar"),
        Some("inv"),
        true,
        Some("bu"),
        Some("usr"),
        Some(5),
        Some(2),
        true,
        Some("/p"),
        Some("l@/q"),
    );
    let (guards, rest) = split_guards(&cmd, context);
    assert_guards(&guards, &["/p", "/q"], &cmd, context);
    let mut words = Words::new(rest, &cmd, context);
    words.next_is_inventory_env();
    words.rest_is(&[
        "ansible",
        "pat",
        "-m",
        "mod",
        "-a",
        "ar",
        "-i",
        "inv",
        "-b",
        "--become-user",
        "bu",
        "-u",
        "usr",
        "-f",
        "5",
        "-vv",
        "-C",
        "--vault-password-file",
        "/p",
        "--vault-id",
        "l@/q",
    ]);

    let context = "distinct values (facts)";
    let cmd = AnsibleCommandBuilder::build_facts_command(
        "pat",
        Some("flt"),
        Some("inv"),
        true,
        Some("bu"),
    );
    let mut words = Words::new(&cmd, &cmd, context);
    words.next_is_inventory_env();
    words.rest_is(&[
        "ansible",
        "pat",
        "-m",
        "setup",
        "-a",
        "filter=flt",
        "-i",
        "inv",
        "-b",
        "--become-user",
        "bu",
    ]);

    // No optional argument: no assignment, no filter.
    let cmd = AnsibleCommandBuilder::build_facts_command("pat", None, None, false, None);
    let mut words = Words::new(&cmd, &cmd, "facts minimal");
    words.rest_is(&["ansible", "pat", "-m", "setup"]);
}

/// The fixed inputs do not depend on `data`, so running them once per process
/// catches a regression as well as running them on every input, and costs
/// nothing per execution. A panic inside `call_once` aborts the run like any
/// assertion.
static FIXED: Once = Once::new();

fuzz_target!(|data: &str| {
    // Fixed inputs: they pin the vault rules that fuzz data rarely reaches.
    FIXED.call_once(|| {
        fixed_vault_cases();
        check_distinct_values();
    });

    // The four ways to name a vault file: both, either one, none. `vault_id`
    // may name no file at all (`prompt`), and may name the same file as
    // `vault_password_file`, so the number of guards is not a constant.
    let vault_cases = [
        (Some(data), Some(data)),
        (Some(data), None),
        (None, Some(data)),
        (None, None),
    ];

    // 1. build_playbook_command
    for (vpf, vid) in vault_cases {
        check_playbook(data, vpf, vid);
    }

    // The same guards as a foreground prefix, with and without a directory.
    for (vpf, vid) in vault_cases {
        check_precheck(Some(data), vpf, vid);
        check_precheck(None, vpf, vid);
    }

    // build_facts_command
    check_facts(data);

    // No optional argument: the program and the playbook, no assignment, no
    // guard.
    let cmd = AnsibleCommandBuilder::build_playbook_command(
        data, None, None, None, None, None, false, false, None, None, false, None, None, None,
        None, None,
    );
    let mut words = Words::new(&cmd, &cmd, "playbook minimal");
    words.next_is("ansible-playbook");
    words.next_is(data);
    words.done();
    assert_arrives_as_text(&cmd, data, "playbook minimal");

    // 2. build_inventory_command (no vault arguments, so no guard)
    let cmd = AnsibleCommandBuilder::build_inventory_command(
        Some(data), // inventory
        true,       // list
        true,       // graph
        Some(data), // host_pattern
        Some(data), // group
        true,       // yaml
        true,       // vars
    );
    assert_arrives_as_text(&cmd, data, "inventory");
    let mut words = Words::new(&cmd, &cmd, "inventory");
    words.next_is_inventory_env();
    words.next_is("ansible-inventory");
    // The command ends with the last flag it writes, so the whole list is
    // exact and no word can be added after it.
    words.next_is("-i");
    words.next_is(data);
    words.rest_is(&[
        "--list", "--graph", data, "--host", data, "--yaml", "--vars",
    ]);

    // Test default action (no list/graph/host), on a fixed input: the program
    // and nothing else but `--list`.
    let cmd = AnsibleCommandBuilder::build_inventory_command(
        None, false, false, None, None, false, false,
    );
    let mut words = Words::new(&cmd, &cmd, "inventory default");
    words.next_is("ansible-inventory");
    words.next_is("--list");
    words.done();

    // 3. build_adhoc_command
    for (vpf, vid) in vault_cases {
        check_adhoc(data, vpf, vid);
    }

    // Test with no optional args: the program, the pattern, the module, no
    // assignment, no guard.
    let cmd = AnsibleCommandBuilder::build_adhoc_command(
        data, "ping", None, None, false, None, None, None, None, false, None, None,
    );
    assert_arrives_as_text(&cmd, data, "adhoc ping");
    let mut words = Words::new(&cmd, &cmd, "adhoc ping");
    words.next_is("ansible");
    words.next_is(data);
    words.next_is("-m");
    words.next_is("ping");
    words.done();
});
