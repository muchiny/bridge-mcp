#![no_main]
use bridge_mcp::domain::use_cases::ldap::LdapCommandBuilder;
use libfuzzer_sys::fuzz_target;

// What the `uri` of the `ssh_ldap_*` tools owes its caller: a `uri` that the
// validator ACCEPTED is exactly one `ldap://`, `ldaps://` or `ldapi://` URI of
// the form `scheme://authority`. In particular it carries nothing that makes
// the client read it as several URIs (a space or a comma separates the URIs of
// `-H`), as user information (`@`), or as a base, a filter or an extension
// (`?`, `#`, a path), and it is not longer than the cap.
//
// The oracle does not parse the URI the way the validator does. It states the
// properties an accepted URI must have whatever the parser decided:
//
// - none of `@`, space, `,`, `?`, `#`, and no whitespace, control or non-ASCII
//   character at all;
// - exactly one `://`;
// - a scheme, read case-insensitively as the client does, of `ldap`, `ldaps`
//   or `ldapi`;
// - after `://`, at most one `/` and only as the last character;
// - at most 255 bytes.
//
// Refusal is always fine; the fuzzer is looking for a `uri` that gets THROUGH.
//
// Run with: `cargo +nightly fuzz run fuzz_ldap_uri`

fuzz_target!(|data: &str| {
    if LdapCommandBuilder::validate_uri(data).is_err() {
        return;
    }

    for forbidden in ['@', ' ', ',', '?', '#'] {
        assert!(
            !data.contains(forbidden),
            "accepted a uri that holds {forbidden:?}: {data:?}"
        );
    }
    assert!(
        data.bytes().all(|b| b.is_ascii_graphic()),
        "accepted a uri with a whitespace, control or non-ASCII character: {data:?}"
    );
    assert_eq!(
        data.matches("://").count(),
        1,
        "accepted a uri that does not hold exactly one ://: {data:?}"
    );
    assert!(
        data.len() <= 255,
        "accepted a uri longer than 255 bytes: {data:?}"
    );

    let Some((scheme, rest)) = data.split_once("://") else {
        panic!("accepted a uri without ://: {data:?}");
    };
    let scheme = scheme.to_ascii_lowercase();
    assert!(
        matches!(scheme.as_str(), "ldap" | "ldaps" | "ldapi"),
        "accepted a uri with the scheme {scheme:?}: {data:?}"
    );
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    assert!(
        !authority.contains('/'),
        "accepted a uri with a path: {data:?}"
    );
});
