#![no_main]

use bridge_mcp::parse_relative_duration;
use libfuzzer_sys::fuzz_target;

// The `history://` half of the resource surface, split out because its
// property has nothing to do with a shell.
//
// `resources/read {"uri": "history://recent?since=200000000000d"}` used to
// ABORT the process. The magnitude was never bounded, so the string reached
// chrono's panicking `Duration::days`, and the release profile sets
// `panic = "abort"` — one malformed URI from one client took down a daemon
// serving every client. Fixed in #171 by the `try_*` constructors and the
// `checked_sub_signed`; this target is what keeps that fix.
//
// "It returns rather than aborts" is the whole point here and is NOT the empty
// assertion it would be elsewhere: the defect this guards was a real abort in
// shipped code, not a hypothetical panic in `serde_json`.
fuzz_target!(|data: &str| {
    let parsed = parse_relative_duration(data);

    // Everything below reads the INPUT, never the returned instant.
    //
    // The instant is `Utc::now() - duration`, so the obvious assertion — "never
    // in the future" — needs a second `Utc::now()` to compare against and is
    // therefore hostage to a wall-clock step backwards (NTP). A target that
    // goes red when the machine's clock is corrected is a target people learn
    // to ignore.
    let Some((_, unit)) = data.char_indices().next_back() else {
        assert!(parsed.is_err(), "an empty duration is not a duration");
        return;
    };

    // A closed set of four units. Anything else must be refused, and this is a
    // membership test rather than a re-parse, so it cannot drift from what the
    // function does.
    if !matches!(unit, 's' | 'm' | 'h' | 'd') {
        assert!(
            parsed.is_err(),
            "{data:?} ends in {unit:?}, which is not one of s/m/h/d, yet it parsed"
        );
        return;
    }

    // A leading `+` is accepted, and legitimately so: `i64::from_str` takes it.
    // An oracle written as "the prefix must be all digits" would call `+5d` a
    // defect and be red on healthy code.
    let number = &data[..data.len() - unit.len_utf8()];
    if parsed.is_ok() {
        let n = number
            .parse::<i64>()
            .unwrap_or_else(|e| panic!("{data:?} parsed, but its prefix {number:?} is not an i64: {e}"));
        assert!(
            n >= 0,
            "{data:?} carries a negative magnitude ({n}) and must not parse: \
             a duration in the future is not a `since`"
        );
    }
});
