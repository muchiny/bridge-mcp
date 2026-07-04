//! Property-based invariants: config serde round-trip, output truncation,
//! output cache pagination.
//!
//! Complements `tests/proptest_commands.rs` (shell escaping + command
//! builders). Any failing case proptest discovers is persisted under
//! `tests/proptest-regressions/` — commit that file: it is a permanent
//! non-regression seed.

use bridge_mcp::config::{SecurityConfig, SecurityMode};
use bridge_mcp::domain::OutputCache;
use bridge_mcp::domain::output_truncator::truncate_output;
use proptest::prelude::*;

proptest! {
    /// YAML round-trip: serialize → deserialize → serialize is a fixed
    /// point for any `SecurityConfig` (guards serde attrs and
    /// `deny_unknown_fields` against field renames/drops).
    ///
    /// `SecurityConfig` has no `PartialEq`, so the fixed point is checked
    /// on the YAML representation instead of the struct.
    #[test]
    fn security_config_yaml_round_trip(
        mode in prop_oneof![
            Just(SecurityMode::Strict),
            Just(SecurityMode::Standard),
            Just(SecurityMode::Permissive),
        ],
        whitelist in proptest::collection::vec("[a-zA-Z0-9 .*+?^$-]{1,40}", 0..5),
        blacklist in proptest::collection::vec("[a-zA-Z0-9 .*+?^$-]{1,40}", 0..5),
    ) {
        let mut cfg = SecurityConfig::default();
        cfg.mode = mode;
        cfg.whitelist = whitelist;
        cfg.blacklist = blacklist;

        let yaml = serde_saphyr::to_string(&cfg).expect("serialize");
        let back: SecurityConfig = serde_saphyr::from_str(&yaml).expect("deserialize");
        let yaml2 = serde_saphyr::to_string(&back).expect("re-serialize");
        prop_assert_eq!(yaml, yaml2);
    }

    /// `truncate_output` never panics (UTF-8 boundary safety on arbitrary
    /// unicode), is the identity when the input fits, and always embeds the
    /// truncation marker otherwise.
    #[test]
    fn truncate_output_utf8_safe(s in "\\PC*", max in 0usize..512) {
        let out = truncate_output(&s, max);
        if max == 0 || s.len() <= max {
            prop_assert_eq!(out, s);
        } else {
            prop_assert!(out.contains("--- [truncated:"));
        }
    }

    /// Any offset/limit combination yields a valid, in-bounds page whose
    /// text is an exact substring of the stored output.
    #[test]
    fn output_cache_pagination_in_bounds(
        s in "\\PC{0,200}",
        offset in 0usize..300,
        limit in 0usize..300,
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let cache = OutputCache::new(300, 10);
            let id = cache.store(s.clone()).await;
            let page = cache.fetch(&id, offset, limit).await.expect("entry alive");
            assert_eq!(page.total_chars, s.len());
            assert!(page.text.len() <= s.len());
            assert!(s.contains(&page.text), "page must be a substring");
            if page.has_more {
                assert!(!page.text.is_empty() || page.offset < s.len());
            }
        });
    }
}
