#![no_main]

use std::cell::RefCell;
use std::sync::OnceLock;

use bridge_mcp::config::{SecurityConfig, SecurityMode};
use bridge_mcp::domain::yaml::parse_yaml;
use bridge_mcp::{CommandValidator, Config, validate_config};
use libfuzzer_sys::fuzz_target;

// Renamed from `fuzz_regex_redos`, because the premise it was named for is
// empty. The `regex` crate has no backtracking: it compiles to an automaton
// with linear-time matching, so `(a+)+$` against a long `a` string — the seed
// the old target shipped — cannot blow up, and no input can make it. A target
// named for a vulnerability the engine does not have measures a hazard that
// does not exist, and its only assertion was "did not panic".
//
// What is actually at stake at this call site is the GRANT. `CommandValidator`
// is the gate every `ssh_exec` passes; in strict and standard mode the
// whitelist is the only thing that opens it. So the questions are:
//
//   1. A pattern the engine REFUSES must grant nothing. `CompiledPatterns::
//      compile` logs the compile error and drops the pattern — deliberately,
//      because a whitelist that loses an entry fails CLOSED. The direction is
//      the whole point: the same silent drop applied to a fallback that
//      admitted everything would fail open, and nothing in the type system
//      distinguishes the two.
//   2. An EMPTY whitelist grants nothing in strict/standard mode. "No rule
//      configured" must not read as "no restriction".
//   3. An empty command is refused in EVERY mode, whatever the lists say. An
//      empty command reaching the far end is a free shell.
//   4. Adding a pattern can only ADD grants. `any`, never `all`.
//
// THE TRAP, found by the refuter and worth naming because it is the assertion
// this target was NOT allowed to make: with a whitelist of `echo.*test`, the
// command `echo${IFS}test` IS legitimately granted. `validate` matches the
// whitelist against the RAW command (only the blacklist sees
// `normalize_for_blacklist_match`), and `.` in the `regex` crate stops at `\n`
// and at nothing else — so `.*` covers `${IFS}` exactly as it covers any other
// bytes. An oracle written from "no shell rewriting may ever produce a match"
// would fail on that input, on healthy code, and would teach whoever reads the
// nightly report to ignore red.
//
// The engine's verdict on a pattern comes from `validate_config`, which is the
// door the operator's config goes through at load and compiles the same
// `regex::Regex`. Asking it, rather than adding `regex` to this crate's
// dependencies, is deliberate: a second copy of the engine could resolve to a
// different version than the product's and disagree about which patterns are
// valid, and an oracle that disagrees with the code on healthy input is worse
// than no oracle. The same reasoning removed `serde-saphyr` from this manifest.

/// A config that validates, carrying one agent-auth host and no patterns.
///
/// Everything the fuzzer varies is written onto [`SCRATCH`], which starts as a
/// copy of this — so the ONLY thing that can make `validate_config` fail below
/// is the whitelist pattern. `type: agent` rather than `type: key` on purpose:
/// key auth stats the file, and a filesystem answer is not a verdict this
/// target can predict.
fn base() -> &'static Config {
    static BASE: OnceLock<Config> = OnceLock::new();
    BASE.get_or_init(|| {
        let document = r#"{"hosts":{"h":{"hostname":"e.internal","user":"u",
            "auth":{"type":"agent"}}},
            "security":{"whitelist":[],"blacklist":[],"sanitize_patterns":[]}}"#;
        let config: Config = parse_yaml(document).expect("the base document must parse");
        assert!(
            validate_config(&config).is_ok(),
            "the base config must validate, or every verdict below is about the \
             wrong thing"
        );
        config
    })
}

thread_local! {
    /// A `Config` reused across iterations, so only its `security` half is
    /// rewritten. Seeded from [`base`], which has already been asserted valid.
    static SCRATCH: RefCell<Config> = RefCell::new(base().clone());
}

/// `^` matches at position 0 of every string, including the empty one, so a
/// whitelist containing it grants every command the emptiness check let past.
const MATCHES_EVERYTHING: &str = "^";

fn take<'a>(data: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if data.len() < n {
        return None;
    }
    let (head, tail) = data.split_at(n);
    *data = tail;
    Some(head)
}

fuzz_target!(|data: &[u8]| {
    let mut rest = data;
    let Some(selector) = take(&mut rest, 1).map(|b| b[0]) else {
        return;
    };
    let Some(pattern_len) = take(&mut rest, 1).map(|b| usize::from(b[0])) else {
        return;
    };
    let Some(pattern_bytes) = take(&mut rest, pattern_len) else {
        return;
    };
    let (Ok(pattern), Ok(command)) =
        (std::str::from_utf8(pattern_bytes), std::str::from_utf8(rest))
    else {
        return;
    };

    let mode = match selector % 3 {
        0 => SecurityMode::Strict,
        1 => SecurityMode::Standard,
        _ => SecurityMode::Permissive,
    };
    let gated = matches!(mode, SecurityMode::Strict | SecurityMode::Standard);

    // The config is mutated in place rather than cloned. `Config` carries the
    // tool-group table and the whole host map, and cloning it three times per
    // iteration cost more than the regex compilations this target exists to
    // drive. libFuzzer runs one input at a time on one thread, so a
    // thread-local is the whole of the synchronisation needed.
    let compiles = SCRATCH.with_borrow_mut(|config| {
        config.security.mode = mode;
        config.security.whitelist.clear();
        config.security.whitelist.push(pattern.to_string());
        // The engine's own verdict, through the product's own door.
        validate_config(config).is_ok()
    });

    let mut security = base().security.clone();
    security.mode = mode;
    security.whitelist = vec![pattern.to_string()];

    let granted = CommandValidator::new(&security).validate(command).is_ok();

    // ------------------------------------------------------------- (3) empty

    // First, because it holds regardless of mode and of what compiled, and
    // because the emptiness check runs before either list is consulted.
    if command.trim().is_empty() {
        assert!(
            !granted,
            "an empty command was granted in {mode:?} mode. It is not a no-op: \
             it is whatever the remote shell does when handed nothing, on a \
             connection this gate is the only thing standing in front of"
        );
        return;
    }

    // -------------------------------------------- (1) a refused pattern grants nothing

    if gated && !compiles {
        assert!(
            !granted,
            "the pattern {pattern:?} does not compile, so it is dropped from \
             the compiled whitelist and nothing is left to match against — yet \
             {command:?} was granted in {mode:?} mode. A whitelist that loses an \
             entry must fail CLOSED"
        );
    }

    // ---------------------------------------------- (2) an empty whitelist grants nothing

    let mut empty: SecurityConfig = security.clone();
    empty.whitelist = Vec::new();
    let granted_by_nothing = CommandValidator::new(&empty).validate(command).is_ok();
    assert_eq!(
        granted_by_nothing,
        !gated,
        "with an EMPTY whitelist, {command:?} must be refused in strict and \
         standard mode and allowed in permissive (the blacklist is empty here). \
         `no rule configured` is not `no restriction`"
    );

    // --------------------------------------------------- (4) adding a pattern only adds

    let mut widened = security.clone();
    widened.whitelist.push(MATCHES_EVERYTHING.to_string());
    let granted_by_widened = CommandValidator::new(&widened).validate(command).is_ok();
    assert!(
        granted_by_widened,
        "the whitelist gained {MATCHES_EVERYTHING:?}, which matches at position \
         0 of every string, yet {command:?} was still refused in {mode:?} mode. \
         A whitelist is a disjunction: an added pattern can only widen it"
    );
    assert!(
        !granted || granted_by_widened,
        "adding a pattern REMOVED a grant for {command:?} in {mode:?} mode"
    );
});
