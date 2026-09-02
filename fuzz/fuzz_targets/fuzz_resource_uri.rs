#![no_main]

use bridge_mcp::{
    file_read_command, log_tail_command, parse_file_uri, parse_log_uri,
};
use bridge_mcp_fuzz::assert_survives_as_one_word;
use libfuzzer_sys::fuzz_target;

// The old target called `serde_json::from_slice::<ResourcesReadParams>` twice
// and asserted nothing beyond "did not panic". That measures `serde_json`, not
// this crate: a URI parser that never panics can still hand a path carrying
// `; id` to a command line, and neither call would notice.
//
// What a resource URI actually does here is reach a shell. `file://{host}/{path}`
// becomes `cat {path}` and `log://{host}/{path}?lines={n}` becomes
// `tail -n {n} {path}`, both through `shell_escape`. The property worth pinning
// is therefore the one the escape exists for: the path the PARSER kept arrives
// in the built command as one intact word, contributing no shell syntax of its
// own.
//
// The path comes from the parser and is never re-derived from the URI text.
// Three oracles in this project have already been wrong rather than the code,
// every one of them by reconstructing what the code under test produced instead
// of asking it; `FileUri`/`LogUri` expose `path` precisely so this target does
// not have to guess.
fuzz_target!(|data: &str| {
    // The two schemes are checked SEPARATELY, and deliberately so.
    //
    // `parse_log_uri` cuts the path at the first `?` because `lines` is a real
    // parameter; `parse_file_uri` does not, because a `cat` takes none — so
    // `file://h/a?b=c` reads a file literally named `/a?b=c`. A single oracle
    // spanning both would have to pick one of those behaviours and would be RED
    // on healthy code for the other. The asymmetry is the product's, not a bug.
    if let Ok(parsed) = parse_file_uri(data) {
        let command = file_read_command(&parsed.path);
        assert_survives_as_one_word(&command, &parsed.path, "file:// -> cat");
    }

    if let Ok(parsed) = parse_log_uri(data) {
        let command = log_tail_command(parsed.lines, &parsed.path);
        assert_survives_as_one_word(&command, &parsed.path, "log:// -> tail -n");
    }

    // Two things this target deliberately does NOT assert.
    //
    // The HOST is never interpolated into a command: it is a key into
    // `ctx.config.hosts` and nothing else, so asserting it survives as a word
    // would be red on every single call — the built command does not contain it
    // at all.
    //
    // And the oracle is `assert_survives_as_one_word`, not
    // `assert_same_shell_skeleton`. The skeleton comparison marks word
    // positions with `\0`, and a path may legitimately CONTAIN a `\0` — a URI
    // is bytes, and nothing upstream strips one. That would corrupt the
    // comparison and produce a failure describing something that never
    // happened.
});
