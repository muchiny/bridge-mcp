#![no_main]

use std::collections::HashMap;

use bridge_mcp::domain::use_cases::shell::refuse_option_like;
use bridge_mcp::domain::yaml::parse_yaml;
use bridge_mcp::{AnsibleCommandBuilder, Config, validate_config};
use libfuzzer_sys::fuzz_target;

// The validators of `AnsibleCommandBuilder` are the security boundary of the
// Ansible tools: they refuse what Ansible would read as an option, as a Jinja
// expression, as an escape it decodes, or as a path that leaves the intended
// directory (GHSA-vcgr-hw4v-9r68).
//
// This target used to assert the 5.0.1 rules in BOTH directions on arbitrary
// input, notably "a playbook path without '..' must be accepted". Since 6.0.0
// that is false (`-rf/otsh$()chmo` starts with '-' and is refused as an
// option), so the target died on its first assertion and every assertion
// after it was dead code.
//
// What it asserts now, for every validator it can reach, is ONE-DIRECTIONAL:
// whatever the validator ACCEPTED satisfies the rule written in its doc
// comment. Refusing more than the rule asks is always fine; the fuzzer is
// looking for values that get THROUGH.
//
// The rules below restate the documented rules; they are not an independent
// oracle. Several are line-for-line copies of the product logic
// (`a_token_may_open_with_equals`, `COMMAND_MODULE_OPTIONS`, the `vault_id`
// source split, the `~user` and `..` source rules), so for those the target
// guards against a regression in the callers (a validator that stops running
// the check, or runs it on the wrong text) and not against a mistake in the
// rule itself. Others (the escape scan, the user name and fact-filter grammars)
// are written differently from the validator and can disagree with it.
//
// Over-refusal (a validator that refuses real input) is not checked here:
// "must accept" cannot be stated on arbitrary data without the next tightening
// of a validator turning the nightly run red. The fixed accept and refuse
// cases are unit tests of `src/domain/use_cases/ansible.rs`, which run in
// `make ci` on every pull request.

/// The Jinja delimiters Ansible would evaluate.
const JINJA: [&str; 3] = ["{{", "{%", "{#"];

/// The patterns `validate_adhoc_module` refuses with a command module.
const DANGEROUS: [&str; 5] = ["rm -rf", "mkfs", "dd if=", "> /dev/", "chmod 777"];

/// The modules that run their arguments as a command line, by their short
/// name: the set `runs_a_command` is documented to match.
const COMMAND_NAMES: [&str; 8] = [
    "command",
    "shell",
    "raw",
    "script",
    "expect",
    "win_command",
    "win_shell",
    "win_powershell",
];

/// Other spellings `runs_a_command` is documented to match: collection-
/// qualified, surrounded by spaces, any case.
const COMMAND_SPELLINGS: [&str; 3] = ["ansible.builtin.shell", "ANSIBLE.LEGACY.RAW", " Shell "];

/// Ansible's special variable names that do not start with `ansible_`, as the
/// "Special Variables" page of the Ansible documentation lists them, plus
/// `delegated_vars`, which the `ssh` connection plugin's `host` option reads
/// with `inventory_hostname`. Written out here, not taken from the product.
const SPECIAL_VARIABLES: [&str; 14] = [
    "delegated_vars",
    "group_names",
    "groups",
    "hostvars",
    "inventory_dir",
    "inventory_file",
    "inventory_hostname",
    "inventory_hostname_short",
    "omit",
    "play_hosts",
    "playbook_dir",
    "role_name",
    "role_names",
    "role_path",
];

/// The inventory plugins that parse their source as data. `script` runs it
/// and `auto` can load a plugin by name; neither may ever be enabled.
const DATA_PLUGINS: [&str; 4] = ["host_list", "yaml", "ini", "toml"];

/// The `key=` words `parse_kv` keeps as options of a command module.
const COMMAND_MODULE_OPTIONS: [&str; 3] = ["executable=", "chdir=", "stdin="];

fn has_jinja(s: &str) -> bool {
    JINJA.iter().any(|t| s.contains(*t))
}

/// Whether `bytes` starts with `n` ASCII hexadecimal digits.
fn starts_with_hex(bytes: &[u8], n: usize) -> bool {
    bytes.len() >= n && bytes[..n].iter().all(u8::is_ascii_hexdigit)
}

/// Whether `s` holds a backslash followed by `U` and 8 hexadecimal digits,
/// `u` and 4, `x` and 2, or `N{`: the escapes Ansible decodes by number or
/// name. Every backslash starts a candidate, paired or not.
fn has_decoded_escape(s: &str) -> bool {
    s.match_indices('\\').any(|(i, _)| {
        let after = &s.as_bytes()[i + 1..];
        match after.first() {
            Some(b'N') => after.get(1) == Some(&b'{'),
            Some(b'U') => starts_with_hex(&after[1..], 8),
            Some(b'u') => starts_with_hex(&after[1..], 4),
            Some(b'x') => starts_with_hex(&after[1..], 2),
            _ => false,
        }
    })
}

/// The file a `vault_id` reads its password from: the part after the first
/// `@`, or the whole value without one. (`prompt` and `prompt_ask_vault_pass`
/// read no file; the rules below hold for them too, so they need no case.)
fn vault_id_source(vault_id: &str) -> &str {
    vault_id.split_once('@').map_or(vault_id, |(_, s)| s)
}

/// Rules on the whole value of `vault_password_file` / `vault_id`.
fn assert_vault_value_rules(arg: &str, value: &str) {
    assert!(
        !has_jinja(value),
        "{arg} accepted with a Jinja delimiter: {value:?}"
    );
    assert!(
        !value.chars().any(char::is_control),
        "{arg} accepted with a control character: {value:?}"
    );
    assert!(
        !value.starts_with('-'),
        "{arg} accepted with a leading '-': {value:?}"
    );
}

/// Rules on the file a vault argument names: no `$` (Ansible expands it), no
/// `~user` (a leading `~` only as `~/`), no `..` path segment (Ansible folds
/// it), no leading `-`.
fn assert_vault_source_rules(arg: &str, source: &str) {
    assert!(
        !source.starts_with('-'),
        "{arg} source accepted with a leading '-': {source:?}"
    );
    assert!(
        !source.contains('$'),
        "{arg} source accepted with '$': {source:?}"
    );
    assert!(
        !(source.starts_with('~') && !source.starts_with("~/")),
        "{arg} source accepted with a '~user' form: {source:?}"
    );
    assert!(
        !source.split('/').any(|segment| segment == ".."),
        "{arg} source accepted with a '..' segment: {source:?}"
    );
}

/// What an accepted `-a` string satisfies, for `module`.
fn assert_adhoc_args_rules(module: &str, args: &str) {
    assert!(
        !has_jinja(args),
        "args accepted with a Jinja delimiter ({module:?}): {args:?}"
    );
    assert!(
        !args.trim().starts_with('{'),
        "args accepted in the JSON form ({module:?}): {args:?}"
    );
    assert!(
        !has_decoded_escape(args),
        "args accepted with an escape Ansible decodes ({module:?}): {args:?}"
    );
    assert!(
        !args.contains("\\="),
        "args accepted with '\\=' ({module:?}): {args:?}"
    );
    // A token may start with `=` at the start of the text, after a space or
    // after a line feed; then no backslash may be left to be decoded.
    let a_token_may_open_with_equals =
        args.starts_with('=') || args.contains(" =") || args.contains("\n=");
    assert!(
        !(a_token_may_open_with_equals && args.contains('\\')),
        "args accepted with a backslash next to a word starting with '=' ({module:?}): {args:?}"
    );
    if AnsibleCommandBuilder::runs_a_command(module) {
        for word in args.split(char::is_whitespace) {
            for option in COMMAND_MODULE_OPTIONS {
                assert!(
                    !word.starts_with(option),
                    "args accepted with '{option}' for a command module ({module:?}): {args:?}"
                );
            }
        }
    }
}

/// What an accepted user name satisfies:
/// `[DOMAIN\]NAME[$]`, NAME starting with a letter or `_`, made of
/// `A-Za-z0-9_.@-`; DOMAIN starting with a letter or digit.
fn assert_user_name_rules(value: &str) {
    for c in value.chars() {
        assert!(
            c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | '-' | '\\' | '$'),
            "user name accepted with {c:?}: {value:?}"
        );
    }
    assert!(
        !value.starts_with('-'),
        "user name accepted with a leading '-': {value:?}"
    );
    assert!(
        value.matches('\\').count() <= 1,
        "user name accepted with several backslashes: {value:?}"
    );
    assert!(
        value.matches('$').count() <= 1 && (!value.contains('$') || value.ends_with('$')),
        "user name accepted with a '$' that is not the single last character: {value:?}"
    );
    let name = value.split_once('\\').map_or(value, |(_, n)| n);
    assert!(
        name.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_'),
        "user name accepted with a NAME that does not start with a letter or '_': {value:?}"
    );
    if let Some((domain, _)) = value.split_once('\\') {
        assert!(
            domain
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric())
                && domain
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
                && domain.chars().count() <= 63,
            "user name accepted with a bad DOMAIN: {value:?}"
        );
    }
    assert!(
        name.strip_suffix('$').unwrap_or(name).chars().count() <= 64,
        "user name accepted with a NAME beyond 64 characters: {value:?}"
    );
    // 63 (domain) + 1 (backslash) + 64 (name) + 1 (`$`).
    assert!(
        value.chars().count() <= 129,
        "user name accepted beyond its length limit: {value:?}"
    );
}

/// What an accepted `setup` filter satisfies: a fact-name glob made of
/// `A-Za-z0-9_*?,` and non-nested `[...]` classes, `!` and `-` only inside a
/// class, no unclosed class.
fn assert_facts_filter_rules(filter: &str) {
    let mut in_class = false;
    for c in filter.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '*' | '?' | ',' => {}
            '[' => {
                assert!(!in_class, "filter accepted with a nested '[': {filter:?}");
                in_class = true;
            }
            ']' => {
                assert!(in_class, "filter accepted with a stray ']': {filter:?}");
                in_class = false;
            }
            '!' | '-' => assert!(
                in_class,
                "filter accepted with {c:?} outside a class: {filter:?}"
            ),
            _ => panic!("filter accepted with {c:?}: {filter:?}"),
        }
    }
    assert!(
        !in_class,
        "filter accepted with an unclosed '[': {filter:?}"
    );
}

/// What an operator-choice check (`accepts(value, allowed)`) must satisfy for
/// the fuzzed `data`. The properties are about how the verdict MOVES when the
/// list changes, so they do not restate the comparison they test:
/// - an empty list refuses everything;
/// - a list whose entries all differ from `data` (a trimmed, extended,
///   spliced or re-cased copy of it) refuses it, however the list is ordered;
/// - add the entry `data` itself and it is accepted, wherever it sits in the
///   list and whatever else is there;
/// - and a list holding only `data` accepts nothing but `data`.
fn assert_exact_choice(arg: &str, data: &str, accepts: impl Fn(&str, &[String]) -> bool) {
    assert!(
        !accepts(data, &[]),
        "{arg} accepted with an empty list: {data:?}"
    );
    let upper = data.to_uppercase();
    let lower = data.to_lowercase();
    let trimmed = data.trim().to_string();
    let variants: Vec<String> = [
        format!("{data} "),
        format!(" {data}"),
        format!("{data},x"),
        format!("x{data}"),
        format!("{data}/"),
        format!("{data}/."),
        upper,
        lower,
        trimmed,
    ]
    .into_iter()
    .filter(|variant| variant != data)
    .collect();
    assert!(
        !accepts(data, &variants),
        "{arg} accepted {data:?} from a list of different spellings: {variants:?}"
    );
    let mut reversed = variants.clone();
    reversed.reverse();
    assert!(
        !accepts(data, &reversed),
        "{arg} verdict depends on the order of the list: {data:?}"
    );
    for at in [0, variants.len() / 2, variants.len()] {
        let mut with_entry = variants.clone();
        with_entry.insert(at, data.to_string());
        assert!(
            accepts(data, &with_entry),
            "{arg} refused its own entry at position {at}: {data:?}"
        );
    }
    let entry = [data.to_string()];
    for variant in &variants {
        assert!(
            !accepts(variant, &entry),
            "{arg} choice accepted {variant:?} for the entry {data:?}"
        );
    }
}

/// The inventory plugins `command` enables, from its leading
/// `ANSIBLE_INVENTORY_ENABLED=` word.
fn enabled_inventory_plugins(command: &str) -> Vec<&str> {
    let word = command
        .strip_prefix("ANSIBLE_INVENTORY_ENABLED=")
        .unwrap_or_else(|| panic!("no leading inventory assignment in {command:?}"));
    let first = word.split(' ').next().unwrap_or_default();
    first.split(',').collect()
}

/// A command that names `inventory` enables data plugins only, and when the
/// value holds a `,` (which Ansible reads as a host list, without resolving
/// it to a path) only `host_list`: that plugin refuses a value naming an
/// existing path, so a file of that name is parsed by no plugin. The other
/// data plugins would parse it.
fn assert_inventory_env_rule(inventory: &str) {
    let commands = [
        AnsibleCommandBuilder::build_facts_command("all", None, Some(inventory), false, None),
        AnsibleCommandBuilder::build_inventory_command(
            Some(inventory),
            true,
            false,
            None,
            None,
            false,
            false,
        ),
    ];
    for command in commands {
        let plugins = enabled_inventory_plugins(&command);
        assert!(
            !plugins.is_empty() && plugins.iter().all(|p| DATA_PLUGINS.contains(p)),
            "inventory {inventory:?} enables {plugins:?}"
        );
        if inventory.contains(',') {
            assert_eq!(
                plugins,
                ["host_list"],
                "host list {inventory:?} enables more than host_list"
            );
        }
    }
}

/// Run `validate_config` on a config whose Ansible lists hold `data`, and
/// assert what it let through. Whitelist and blacklist are emptied: the
/// default blacklist is dozens of regexes recompiled per iteration, and
/// regex validity has nothing to do with this rule.
fn assert_loader_rules(data: &str) {
    let list = |key: &str| {
        let mut ansible = serde_json::Map::new();
        ansible.insert(key.to_string(), serde_json::json!([data]));
        let document = serde_json::json!({
            "hosts": {"h": {
                "hostname": "e.internal",
                "user": "u",
                "auth": {"type": "agent"},
                "ansible": ansible,
            }},
            "security": {"whitelist": [], "blacklist": []},
        })
        .to_string();
        // A string a YAML reader cannot take is refused before the loader
        // sees it; there is nothing to check then.
        let config: Config = parse_yaml(&document).ok()?;
        Some(validate_config(&config).is_ok())
    };
    let shared = |entry: &str| {
        !entry.is_empty()
            && !entry.chars().any(char::is_control)
            && !entry.starts_with('-')
            && !has_jinja(entry)
    };
    let plain_absolute = |path: &str| {
        path.starts_with('/')
            && !path.ends_with('/')
            && !path.split('/').any(|segment| segment == "." || segment == "..")
    };

    if list("inventories") == Some(true) {
        assert!(shared(data), "inventories entry accepted: {data:?}");
        if data.contains(',') {
            assert!(!data.contains('/'), "host list with '/' accepted: {data:?}");
        } else {
            assert!(
                plain_absolute(data) && !data.contains('$') && !data.contains('~'),
                "inventory path that Ansible could resolve elsewhere accepted: {data:?}"
            );
        }
    }
    if list("working_dirs") == Some(true) {
        assert!(shared(data), "working_dirs entry accepted: {data:?}");
        assert!(
            plain_absolute(data),
            "working_dirs entry accepted: {data:?}"
        );
    }
}

fuzz_target!(|data: &str| {
    // 1. Positional arguments that must not be read as an option: a leading
    //    '-' is refused by the shared helper and by every validator that
    //    hands the value to Ansible as a positional argument or to `-i`.
    //    The two path validators also refuse any '..' (directory traversal).
    if data.starts_with('-') {
        assert!(
            refuse_option_like("arg", data).is_err(),
            "refuse_option_like let through {data:?}"
        );
    }
    let playbook = AnsibleCommandBuilder::validate_playbook_path(data);
    let lint_target = AnsibleCommandBuilder::validate_lint_target(data);
    let inventory = AnsibleCommandBuilder::validate_inventory(data);
    let pattern = AnsibleCommandBuilder::validate_pattern(data);
    if playbook.is_ok() {
        assert!(
            !data.starts_with('-'),
            "playbook {data:?} reads as an option"
        );
        assert!(!data.contains(".."), "playbook {data:?} holds '..'");
    }
    if lint_target.is_ok() {
        assert!(
            !data.starts_with('-'),
            "lint target {data:?} reads as an option"
        );
        assert!(!data.contains(".."), "lint target {data:?} holds '..'");
    }
    if inventory.is_ok() {
        assert!(
            !data.starts_with('-'),
            "inventory {data:?} reads as an option"
        );
    }
    if pattern.is_ok() {
        assert!(
            !data.starts_with('-'),
            "pattern {data:?} reads as an option"
        );
    }
    // `..` is refused whatever else the path holds.
    if data.contains("..") {
        assert!(playbook.is_err(), "playbook with '..' accepted: {data:?}");
        assert!(
            lint_target.is_err(),
            "lint target with '..' accepted: {data:?}"
        );
    }

    // 2. Vault password file / vault id: Ansible expands `$VAR` and `~user`
    //    and folds `..` before it looks at the file, so none of them may
    //    reach it. Checked on each argument alone and on both together; what
    //    is accepted together is accepted alone.
    let vault_file = AnsibleCommandBuilder::validate_vault_args(Some(data), None);
    if vault_file.is_ok() {
        assert_vault_value_rules("vault_password_file", data);
        assert_vault_source_rules("vault_password_file", data);
    }
    let vault_id = AnsibleCommandBuilder::validate_vault_args(None, Some(data));
    if vault_id.is_ok() {
        assert_vault_value_rules("vault_id", data);
        assert_vault_source_rules("vault_id", vault_id_source(data));
    }
    if AnsibleCommandBuilder::validate_vault_args(Some(data), Some(data)).is_ok() {
        assert!(
            vault_file.is_ok() && vault_id.is_ok(),
            "both vault arguments accepted together but not alone: {data:?}"
        );
    }
    // A fuzzed `vault_id` source behind a fixed label, and the label itself
    // fuzzed: the source is what follows the first '@'.
    let labelled = format!("label@{data}");
    if AnsibleCommandBuilder::validate_vault_args(None, Some(&labelled)).is_ok() {
        assert_vault_value_rules("vault_id", &labelled);
        assert_vault_source_rules("vault_id", vault_id_source(&labelled));
        assert_vault_source_rules("vault_id", data);
    }

    // 3. Jinja: a delimiter in the text is refused, alone or in a list.
    let jinja = AnsibleCommandBuilder::refuse_jinja("arg", data);
    if has_jinja(data) {
        assert!(jinja.is_err(), "Jinja accepted by refuse_jinja: {data:?}");
    }
    if AnsibleCommandBuilder::refuse_jinja_in(&[("first", None), ("second", Some(data))]).is_ok() {
        assert!(
            !has_jinja(data),
            "Jinja accepted by refuse_jinja_in: {data:?}"
        );
    }

    // 4. Free-form `-a` arguments, for command and non-command modules, and
    //    with the module name fuzzed too. A command module never gets a
    //    `chdir=` / `executable=` / `stdin=` word.
    for module in [
        "shell",
        "command",
        "ansible.builtin.raw",
        "win_shell",
        "copy",
        "ping",
    ] {
        if AnsibleCommandBuilder::validate_adhoc_args(module, data).is_ok() {
            assert_adhoc_args_rules(module, data);
        }
    }
    if AnsibleCommandBuilder::validate_adhoc_args(data, data).is_ok() {
        assert_adhoc_args_rules(data, data);
    }
    for option_word in ["executable=/bin/sh", "chdir=/tmp", "stdin=x"] {
        if AnsibleCommandBuilder::validate_adhoc_args(data, option_word).is_ok() {
            assert!(
                !AnsibleCommandBuilder::runs_a_command(data),
                "{option_word} accepted for the command module {data:?}"
            );
        }
    }

    // 5. Which modules run a command line, and what the policy judges. A
    //    module that runs a command is judged by its args alone; any other
    //    module's text starts with `ansible-module`, so a whitelist pattern
    //    written for a shell command cannot match it.
    if AnsibleCommandBuilder::runs_a_command(data) {
        let tail = data.trim().to_ascii_lowercase();
        assert!(
            COMMAND_NAMES.iter().any(|name| tail.ends_with(*name)),
            "runs_a_command true for {data:?}"
        );
    }
    for args in [None, Some(data)] {
        let text = AnsibleCommandBuilder::adhoc_policy_text(data, args);
        if AnsibleCommandBuilder::runs_a_command(data) {
            assert_eq!(
                text,
                args.map(str::to_owned),
                "policy text of a command module {data:?}"
            );
        } else if let Some(text) = text {
            assert!(
                text.starts_with("ansible-module"),
                "policy text of module {data:?}: {text:?}"
            );
        }
    }
    if let Some(text) = AnsibleCommandBuilder::adhoc_policy_text("copy", Some(data)) {
        assert!(
            text.starts_with("ansible-module copy"),
            "policy text of 'copy' with args {data:?}: {text:?}"
        );
    }

    // 6. validate_adhoc_module: a module that runs a command line (bare,
    //    collection-qualified, any case) is refused when its args hold a
    //    dangerous pattern; the match is case-insensitive.
    let lower = data.to_lowercase();
    for module in COMMAND_NAMES.into_iter().chain(COMMAND_SPELLINGS) {
        let verdict = AnsibleCommandBuilder::validate_adhoc_module(module, Some(data));
        for pattern in &DANGEROUS {
            if lower.contains(*pattern) {
                assert!(
                    verdict.is_err(),
                    "Dangerous pattern '{pattern}' with module {module:?} accepted: {data:?}"
                );
            }
        }
    }
    // The module name fuzzed: only a module that runs no command line gets
    // dangerous args through.
    if AnsibleCommandBuilder::validate_adhoc_module(data, Some("rm -rf /")).is_ok() {
        assert!(
            !AnsibleCommandBuilder::runs_a_command(data),
            "'rm -rf /' accepted for the command module {data:?}"
        );
    }

    // 7. Become / connection user name: [DOMAIN\]NAME[$], nothing a shell
    //    reads. `arg` only names the field in the error.
    if AnsibleCommandBuilder::validate_user_name("become_user", data).is_ok() {
        assert_user_name_rules(data);
    }

    // 8. Fact filter of `ansible -m setup`: a fact-name glob only.
    if AnsibleCommandBuilder::validate_facts_filter(data).is_ok() {
        assert_facts_filter_rules(data);
    }

    // 9. Playbook extra variables: the key is a plain identifier outside the
    //    `ansible_` connection variables or Ansible's other special variables;
    //    the value holds no Jinja.
    let by_key = HashMap::from([(data.to_string(), "v".to_string())]);
    if AnsibleCommandBuilder::validate_extra_vars(&by_key).is_ok() {
        let mut chars = data.chars();
        assert!(
            chars
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "extra_vars key accepted: {data:?}"
        );
        assert!(
            !data.starts_with("ansible_"),
            "extra_vars connection variable accepted: {data:?}"
        );
        assert!(
            !SPECIAL_VARIABLES.contains(&data),
            "extra_vars special variable accepted: {data:?}"
        );
    }
    let by_value = HashMap::from([("k".to_string(), data.to_string())]);
    if AnsibleCommandBuilder::validate_extra_vars(&by_value).is_ok() {
        assert!(
            !has_jinja(data),
            "extra_vars value with Jinja accepted: {data:?}"
        );
    }

    // 10. Stdout callback: a name, never shell syntax. (The allow list is
    //     private; this is the shape every entry has.)
    if AnsibleCommandBuilder::validate_callback(data).is_ok() {
        assert!(
            !data.is_empty()
                && data
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')),
            "callback accepted: {data:?}"
        );
    }

    // 11. Values the operator lists in `hosts.<host>.ansible` (inventory,
    //     remote user, working directory): the match is an exact string
    //     comparison, so a value gets through only when it IS an entry. An
    //     empty list refuses everything, and a value that merely contains,
    //     extends or splices an entry is not that entry.
    assert_exact_choice("inventory", data, |value, allowed| {
        AnsibleCommandBuilder::validate_inventory_choice("host", value, allowed).is_ok()
    });
    assert_exact_choice("user", data, |value, allowed| {
        AnsibleCommandBuilder::validate_remote_user_choice("host", value, allowed).is_ok()
    });
    assert_exact_choice("working_dir", data, |value, allowed| {
        AnsibleCommandBuilder::validate_working_dir_choice("host", value, allowed).is_ok()
    });

    // 12. An inventory that holds a ',' is a host list to Ansible, which does
    //     not resolve it to a path. Only `host_list` may be enabled for it.
    assert_inventory_env_rule(data);
    assert_inventory_env_rule(&format!("{data},"));

    // 13. What the config loader lets into the `hosts.<host>.ansible` lists.
    assert_loader_rules(data);
});
