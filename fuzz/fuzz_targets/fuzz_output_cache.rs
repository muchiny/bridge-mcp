#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::output_cache::OutputCache;

fuzz_target!(|data: (u16, u16, &str)| {
    let (offset_raw, limit_raw, content) = data;
    let offset = offset_raw as usize;
    let limit = (limit_raw as usize).max(1);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let cache = OutputCache::new(300, 100);
        let id = cache.store(content.to_string()).await;

        // Fetch with fuzzed offset/limit
        if let Some(result) = cache.fetch(&id, offset, limit).await {
            assert_eq!(result.total_chars, content.len());
            if offset >= content.len() {
                assert!(result.text.is_empty());
                assert!(!result.has_more);
            }
        }

        // Fetch nonexistent
        assert!(cache.fetch("nonexistent", 0, 100).await.is_none());
        cache.cleanup().await;
    });
});
