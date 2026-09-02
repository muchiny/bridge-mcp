#![no_main]

use bridge_mcp::domain::yaml::parse_yaml;
use bridge_mcp::{validate_config, Config, SecurityConfig};
use libfuzzer_sys::fuzz_target;

// The old target called `serde_saphyr::from_str::<SecurityConfig>` on raw
// bytes, then `serde_json::from_slice`, and asserted nothing beyond "did not
// panic". Random bytes are not a security config: the overwhelming majority of
// them fail at the first token, so the target spent its budget proving that a
// YAML parser rejects garbage.
//
// This one BUILDS a document instead, and asks two questions the old one could
// not reach.
//
// Half A — no default is invented, and none is lost. A config that silently
// gains a permissive setting the operator never wrote, or silently drops a
// restrictive one they did, is the whole failure mode of a security config.
//
// Half B — a threshold no token could ever meet is refused. `EntropyDetector`
// decides with `entropy >= threshold`; against NaN that comparison is ALWAYS
// false, so a NaN threshold leaves the detector enabled, running, and redacting
// nothing — fail-open, on the path that masks secrets out of command output.
// serde-saphyr parses `.nan` and `.inf` into a concrete f64 without complaint.
// Fixed in #171 by `validate_entropy_thresholds`; this is what keeps it.
//
// The document is serialised as JSON, which is valid YAML 1.2. That is what
// stops a hostile STRING from promoting itself to a key: `serde_json` escapes
// the quotes, so a whitelist entry reading `a": {"mode": "permissive` stays one
// string instead of becoming a mode override. Half A asserts exactly that.

/// Render an f64 as a YAML scalar, including the three JSON cannot carry.
///
/// `serde_json` refuses to serialise NaN and the infinities — it has no
/// representation for them — so the two threshold slots are written by hand.
/// An f64 has no way to inject a key whatever its value, so nothing is lost by
/// stepping outside JSON for these two and only these two.
fn yaml_f64(v: f64) -> String {
    if v.is_nan() {
        ".nan".to_string()
    } else if v == f64::INFINITY {
        ".inf".to_string()
    } else if v == f64::NEG_INFINITY {
        "-.inf".to_string()
    } else {
        // `{:?}` on f64 round-trips and always emits a decimal point or an
        // exponent, so the scalar cannot be read back as an integer.
        format!("{v:?}")
    }
}

fn take<'a>(data: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if data.len() < n {
        return None;
    }
    let (head, tail) = data.split_at(n);
    *data = tail;
    Some(head)
}

fn take_f64(data: &mut &[u8]) -> Option<f64> {
    let bytes = take(data, 8)?;
    Some(f64::from_bits(u64::from_be_bytes(bytes.try_into().ok()?)))
}

fuzz_target!(|data: &[u8]| {
    let mut rest = data;
    let Some(flags) = take(&mut rest, 1).map(|b| b[0]) else {
        return;
    };
    let Some(threshold) = take_f64(&mut rest) else {
        return;
    };
    let Some(hex_threshold) = take_f64(&mut rest) else {
        return;
    };
    // Whatever is left is a caller-controlled string. It goes into `whitelist`,
    // which is a `Vec<String>` the operator writes by hand — the most plausible
    // place for a value that tries to be a key.
    let Ok(entry) = std::str::from_utf8(rest) else {
        return;
    };

    // ---------------------------------------------------------------- Half A

    let write_mode = flags & 1 != 0;
    let write_whitelist = flags & 2 != 0;
    let write_entropy_detection = flags & 4 != 0;

    let mut security = serde_json::Map::new();
    if write_mode {
        security.insert("mode".into(), serde_json::json!("permissive"));
    }
    if write_whitelist {
        security.insert("whitelist".into(), serde_json::json!([entry]));
    }
    if write_entropy_detection {
        security.insert(
            "sanitize".into(),
            serde_json::json!({"entropy_detection": false}),
        );
    }
    let document = serde_json::json!({ "security": security }).to_string();

    let parsed: Config = match parse_yaml(&document) {
        Ok(c) => c,
        // A whitelist entry can carry any bytes, and not all of them survive a
        // YAML reader — a lone `\r` in a JSON string is legal JSON and a line
        // break to YAML. Refusing the document is a legitimate outcome; what
        // must not happen is accepting it and reading it WRONG, which is what
        // everything below checks.
        Err(_) => return,
    };
    let defaults = SecurityConfig::default();

    // Nothing invented: every key the document did not carry must still hold
    // the type's own default.
    if !write_mode {
        assert_eq!(
            parsed.security.mode, defaults.mode,
            "`mode` was not written, so it must be the default: {document}"
        );
    }
    if !write_whitelist {
        assert!(
            parsed.security.whitelist.is_empty(),
            "`whitelist` was not written, so nothing may be in it: {:?}",
            parsed.security.whitelist
        );
    }
    if !write_entropy_detection {
        assert_eq!(
            parsed.security.sanitize.entropy_detection, defaults.sanitize.entropy_detection,
            "`entropy_detection` was not written, so it must be the default"
        );
    }

    // Nothing lost, and nothing promoted: the string the caller wrote comes
    // back as ONE whitelist entry, byte for byte. If it had escaped its scalar
    // and become a key, either the vector would not hold it or `mode` would
    // have changed underneath us.
    if write_whitelist {
        assert_eq!(
            parsed.security.whitelist,
            vec![entry.to_string()],
            "a whitelist entry did not survive as itself: {document}"
        );
        if !write_mode {
            assert_eq!(
                parsed.security.mode, defaults.mode,
                "a whitelist STRING changed the security mode — it escaped its \
                 scalar and became a key: {document}"
            );
        }
    }

    // ---------------------------------------------------------------- Half B

    // A second document, otherwise valid and fixed, so the ONLY variable is the
    // pair of thresholds. `type: agent` deliberately: `validate_config` stats
    // the key file for `type: key`, and a filesystem answer is not a decision
    // this target can predict.
    // `whitelist` and `blacklist` are emptied on purpose. `validate_config`
    // compiles every pattern in both, and the DEFAULT blacklist is dozens of
    // regexes — recompiling them per iteration cost this target 97% of its
    // throughput (4 467 executions per two minutes against 342 863 once emptied)
    // while testing a constant that cannot vary. Regex validity is orthogonal
    // to a threshold's range and belongs to a unit test.
    let thresholds = format!(
        "{{\"hosts\":{{\"h\":{{\"hostname\":\"e.internal\",\"user\":\"u\",\
           \"auth\":{{\"type\":\"agent\"}}}}}},\
          \"security\":{{\"whitelist\":[],\"blacklist\":[],\
           \"sanitize\":{{\"entropy_threshold\":{},\
           \"entropy_hex_threshold\":{}}}}}}}",
        yaml_f64(threshold),
        yaml_f64(hex_threshold),
    );
    let Ok(config) = parse_yaml::<Config>(&thresholds) else {
        return;
    };

    // Read the thresholds back from the PARSED config rather than from the two
    // f64s that went in. A YAML round-trip is not the identity on every f64 —
    // subnormals and the extremes of the exponent range are exactly where it
    // might not be — and an oracle comparing the verdict against the input
    // would be measuring the round-trip, not the validation.
    let acceptable = |v: f64| v.is_finite() && (0.0..=8.0).contains(&v);
    let both_acceptable = acceptable(config.security.sanitize.entropy_threshold)
        && config
            .security
            .sanitize
            .entropy_hex_threshold
            .is_none_or(acceptable);

    assert_eq!(
        validate_config(&config).is_ok(),
        both_acceptable,
        "the entropy thresholds decide this config's fate and nothing else does. \
         Shannon entropy over bytes is capped at 8 bits, and `entropy >= NaN` is \
         always false, so a threshold outside 0..=8 or not finite leaves the \
         detector running and redacting nothing.\n  document: {thresholds}\n  \
         verdict: {:?}",
        validate_config(&config).err()
    );
});
