#![no_main]

use bridge_mcp::domain::yaml::parse_yaml;
use bridge_mcp::Config;
use libfuzzer_sys::fuzz_target;

// The old target called `serde_saphyr::from_str::<Config>` BARE and asserted
// nothing beyond "did not panic". Two things were wrong with that.
//
// It went through the wrong door. Production parses config through
// `domain::yaml::parse_yaml`, which applies `hardened_options()`: the anti-DoS
// budget (1 MiB / 100 anchors / 1000 aliases / depth 50 / 10 000 nodes) and,
// the part that matters here, `with_snippet: false`. The bare call has none of
// them, so the target exercised a parser configuration the product does not
// use — a CONFIGURATION drift, not the version drift it was once mistaken for
// (root and the fuzz crate both resolve serde-saphyr 1.1.0).
//
// And it could not have seen the defect that lived there. saphyr renders three
// lines of the input around a fault, rustc-style. That is helpful right up to
// the moment the neighbouring line is `password:` — and a config file puts one
// within three lines of a syntax error by construction. The message goes to
// stderr at startup and on every failed hot-reload, so it lands in the MCP
// client's log in plaintext, and the Sanitizer cannot mask it: its
// `known_secrets` come from a Config that LOADED, which by definition does not
// exist when parsing failed. Fixed in #171 by `with_snippet: false`; this
// target is what keeps it.
//
// The document is a fixed PREFIX carrying two secrets, plus the fuzzed bytes.
// The prefix contains no YAML anchor, deliberately: with one, the fuzzed bytes
// could alias the secret and make it reappear LEGITIMATELY, and the target
// would be red on healthy code.
const SENTINEL: &str = "Zq7vN3xK9mWpL5tR8bY2cF6hJ4dS0gA1eU";

const PREFIX: &str = concat!(
    "hosts:\n",
    "  prod:\n",
    "    hostname: example.internal\n",
    "    user: deploy\n",
    "    sudo_password: Zq7vN3xK9mWpL5tR8bY2cF6hJ4dS0gA1eU\n",
    "    auth:\n",
    "      type: password\n",
    "      password: Zq7vN3xK9mWpL5tR8bY2cF6hJ4dS0gA1eU\n",
);

/// Shortest run of secret bytes worth failing on.
///
/// "No byte of the sentinel" cannot be read literally — `a` is a byte of it and
/// appears in every English error message. A 12-byte window of a random
/// alphanumeric string is what actually distinguishes "the parser echoed the
/// secret" from a coincidence.
const WINDOW: usize = 12;

fuzz_target!(|data: &str| {
    // The target must not be vacuous. If the prefix stopped being a valid
    // config — a renamed field, a changed enum tag — every parse below would
    // fail at line 1, the secret would never be reached, and the assertions
    // would pass forever while testing nothing. This is the check that says so
    // out loud.
    assert!(
        parse_yaml::<Config>(PREFIX).is_ok(),
        "the prefix is no longer a valid config, so this target proves nothing"
    );

    let document = format!("{PREFIX}{data}");
    let Err(error) = parse_yaml::<Config>(&document) else {
        return;
    };
    let message = error.to_string();

    for start in 0..=SENTINEL.len() - WINDOW {
        let window = &SENTINEL[start..start + WINDOW];

        // The fuzzer WILL discover the sentinel: comparing against it is
        // exactly the comparison libFuzzer instruments and feeds back. Once it
        // types the secret into `data` itself, a parser echoing the offending
        // scalar is quoting the input, not leaking the config — and asserting
        // otherwise would make this target red on healthy code the moment the
        // fuzzer got good at its job.
        if data.contains(window) {
            continue;
        }

        assert!(
            !message.contains(window),
            "a parse error carried {window:?}, which is {} bytes of a secret the \
             caller never wrote — this message goes to stderr in plaintext, and \
             the Sanitizer cannot mask it because no config loaded.\n  \
             appended: {data:?}\n  error: {message}",
            WINDOW
        );
    }
});
