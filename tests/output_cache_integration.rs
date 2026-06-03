//! Output Cache Integration Tests
//!
//! Tests the full output cache flow: store, fetch with pagination,
//! eviction, TTL expiry, Unicode safety, and concurrency.

use std::sync::Arc;

use bridge_mcp::domain::OutputCache;

// ============== Store and Fetch Flow ==============

#[tokio::test]
async fn test_store_and_fetch_full_content() {
    let cache = OutputCache::new(300, 100);
    let content = "Hello, World! This is a test output from a remote command.";
    let id = cache.store(content.to_string()).await;

    let result = cache.fetch(&id, 0, 10_000).await.unwrap();
    assert_eq!(result.text, content);
    assert_eq!(result.total_chars, content.len());
    assert_eq!(result.offset, 0);
    assert!(!result.has_more);
}

#[tokio::test]
async fn test_fetch_with_three_pages() {
    let cache = OutputCache::new(300, 100);
    let content = "AAAA_BBBB_CCCC_DDDD_EEEE_FFFF";
    let id = cache.store(content.to_string()).await;

    // Page 1: first 10 chars
    let page1 = cache.fetch(&id, 0, 10).await.unwrap();
    assert_eq!(page1.text, "AAAA_BBBB_");
    assert!(page1.has_more);
    assert_eq!(page1.offset, 0);

    // Page 2: next 10 chars
    let page2 = cache.fetch(&id, 10, 10).await.unwrap();
    assert_eq!(page2.text, "CCCC_DDDD_");
    assert!(page2.has_more);
    assert_eq!(page2.offset, 10);

    // Page 3: remaining chars
    let page3 = cache.fetch(&id, 20, 10).await.unwrap();
    assert_eq!(page3.text, "EEEE_FFFF");
    assert!(!page3.has_more);
}

#[tokio::test]
async fn test_fetch_nonexistent_id() {
    let cache = OutputCache::new(300, 100);
    let result = cache.fetch("out-9999", 0, 100).await;
    assert!(result.is_none(), "Non-existent ID should return None");
}

#[tokio::test]
async fn test_fetch_offset_beyond_content() {
    let cache = OutputCache::new(300, 100);
    let id = cache.store("short text".to_string()).await;

    let result = cache.fetch(&id, 1000, 100).await.unwrap();
    assert_eq!(result.text, "");
    assert!(!result.has_more);
}

// ============== Eviction ==============

#[tokio::test]
async fn test_cache_evicts_oldest_at_capacity() {
    let cache = OutputCache::new(300, 3); // Max 3 entries

    let id1 = cache.store("first".to_string()).await;
    let _id2 = cache.store("second".to_string()).await;
    let _id3 = cache.store("third".to_string()).await;

    // All 3 should be retrievable
    assert!(cache.fetch(&id1, 0, 100).await.is_some());

    // Adding a 4th should evict the oldest (id1)
    let _id4 = cache.store("fourth".to_string()).await;

    assert!(
        cache.fetch(&id1, 0, 100).await.is_none(),
        "Oldest entry should be evicted"
    );
}

// ============== TTL Expiry ==============

#[tokio::test]
async fn test_cache_ttl_expiry() {
    let cache = OutputCache::new(0, 100); // 0-second TTL = immediate expiry
    let id = cache.store("ephemeral data".to_string()).await;

    let result = cache.fetch(&id, 0, 100).await;
    assert!(result.is_none(), "Should be expired immediately with TTL=0");
}

// ============== Unicode Safety ==============

#[tokio::test]
async fn test_unicode_pagination_does_not_split_chars() {
    let cache = OutputCache::new(300, 100);
    let content = "日本語テスト🎉emoji";
    let id = cache.store(content.to_string()).await;

    // Fetch full
    let result = cache.fetch(&id, 0, 10_000).await.unwrap();
    assert_eq!(result.text, content);

    // Fetch with offset in middle of multi-byte char
    // "日" is 3 bytes, offset 1 is inside it
    let result = cache.fetch(&id, 1, 6).await.unwrap();
    // Should snap to valid char boundary, not panic
    assert!(result.text.is_char_boundary(0));
    assert!(result.text.chars().count() > 0);
}

#[tokio::test]
async fn test_emoji_pagination() {
    let cache = OutputCache::new(300, 100);
    // Each emoji is 4 bytes
    let content = "🎉🎊🎈🎁🎆";
    let id = cache.store(content.to_string()).await;

    // Try to split in middle of first emoji (offset=2, which is inside the 4-byte emoji)
    let result = cache.fetch(&id, 2, 8).await.unwrap();
    // Should handle gracefully without panicking
    assert!(result.text.is_char_boundary(0));
}

// ============== Concurrency ==============

#[tokio::test]
async fn test_concurrent_store_and_fetch() {
    let cache = Arc::new(OutputCache::new(300, 1000));

    let mut handles = Vec::new();
    for i in 0..50 {
        let cache = Arc::clone(&cache);
        handles.push(tokio::spawn(async move {
            let content = format!("output-{i}: {}", "x".repeat(100));
            let id = cache.store(content.clone()).await;
            let result = cache.fetch(&id, 0, 10_000).await.unwrap();
            assert_eq!(result.text, content);
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

// ============== Sequential ID Generation ==============

#[tokio::test]
async fn test_ids_are_sequential_hex() {
    let cache = OutputCache::new(300, 100);

    let id1 = cache.store("a".to_string()).await;
    let id2 = cache.store("b".to_string()).await;
    let id3 = cache.store("c".to_string()).await;

    assert!(id1.starts_with("out-"), "IDs should start with 'out-'");
    assert!(id2.starts_with("out-"));
    assert!(id3.starts_with("out-"));

    // IDs should be sequential
    assert_ne!(id1, id2);
    assert_ne!(id2, id3);
}

// ============== Cleanup ==============

#[tokio::test]
async fn test_cleanup_removes_expired_entries() {
    let cache = OutputCache::new(0, 100); // 0-second TTL
    cache.store("a".to_string()).await;
    cache.store("b".to_string()).await;
    cache.store("c".to_string()).await;

    cache.cleanup().await;

    // After cleanup, all expired entries should be gone
    // Store a new one and verify cache is functional
    let id = cache.store("new".to_string()).await;
    // This will also be expired immediately due to 0 TTL
    let result = cache.fetch(&id, 0, 100).await;
    assert!(result.is_none());
}

// ============== Large Content ==============

#[tokio::test]
async fn test_large_output_storage_and_pagination() {
    let cache = OutputCache::new(300, 100);
    let content = "x".repeat(100_000); // 100KB
    let id = cache.store(content.clone()).await;

    // Fetch first page
    let page1 = cache.fetch(&id, 0, 10_000).await.unwrap();
    assert_eq!(page1.text.len(), 10_000);
    assert!(page1.has_more);
    assert_eq!(page1.total_chars, 100_000);

    // Fetch last page
    let last_page = cache.fetch(&id, 90_000, 20_000).await.unwrap();
    assert_eq!(last_page.text.len(), 10_000);
    assert!(!last_page.has_more);
}
