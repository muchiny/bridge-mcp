//! Output Cache
//!
//! Thread-safe cache for full command outputs that were truncated.
//! Enables paginated retrieval via `ssh_output_fetch` tool.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::RwLock;
// tokio Instant (not std): honors tokio::time::pause/advance in tests, so
// TTL boundaries are deterministically testable. Identical API otherwise.
use tokio::time::Instant;

use super::output_truncator::ceil_char_boundary;

/// Cached output entry with creation timestamp for TTL expiration.
struct CacheEntry {
    output: String,
    created: Instant,
}

/// Result of fetching a page from the output cache.
#[derive(Debug, Clone)]
pub struct FetchResult {
    /// The requested slice of output text
    pub text: String,
    /// Total characters in the full cached output
    pub total_chars: usize,
    /// Character offset this page starts at
    pub offset: usize,
    /// Whether more content exists beyond this page
    pub has_more: bool,
}

/// Thread-safe output cache with TTL-based expiration and counter-based IDs.
///
/// When a tool's output is truncated, the full output is stored here.
/// The LLM can then use `ssh_output_fetch` with the assigned `output_id`
/// to retrieve pages of the full output.
pub struct OutputCache {
    entries: RwLock<HashMap<String, CacheEntry>>,
    counter: AtomicU64,
    ttl: Duration,
    max_entries: usize,
}

impl OutputCache {
    /// Create a new output cache.
    ///
    /// - `ttl_seconds`: How long entries are kept before expiration.
    /// - `max_entries`: Maximum number of entries; oldest are evicted when full.
    #[must_use]
    pub fn new(ttl_seconds: u64, max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            counter: AtomicU64::new(0),
            ttl: Duration::from_secs(ttl_seconds),
            max_entries,
        }
    }

    /// Store a full output and return the assigned ID (e.g., `out-0000`).
    ///
    /// Expired entries are cleaned up lazily on each store.
    /// If at capacity after cleanup, the oldest entry is evicted.
    pub async fn store(&self, output: String) -> String {
        let id = {
            let n = self.counter.fetch_add(1, Ordering::Relaxed);
            format!("out-{n:04x}")
        };

        let mut entries = self.entries.write().await;

        // Lazy cleanup: remove expired entries
        let now = Instant::now();
        entries.retain(|_, entry| now.duration_since(entry.created) < self.ttl);

        // Evict oldest if at capacity.
        // IDs are monotonically increasing (out-0000, out-0001, ...),
        // so the lexicographic minimum key is always the oldest entry.
        if entries.len() >= self.max_entries
            && let Some(oldest_key) = entries.keys().min().cloned()
        {
            entries.remove(&oldest_key);
        }

        entries.insert(
            id.clone(),
            CacheEntry {
                output,
                created: Instant::now(),
            },
        );

        id
    }

    /// Fetch a page of cached output by ID.
    ///
    /// - `offset`: Character offset to start from (0-based).
    /// - `limit`: Maximum characters to return.
    ///
    /// Returns `None` if the ID is not found or has expired.
    pub async fn fetch(&self, id: &str, offset: usize, limit: usize) -> Option<FetchResult> {
        let entries = self.entries.read().await;
        let entry = entries.get(id)?;

        // Check TTL
        if Instant::now().duration_since(entry.created) >= self.ttl {
            return None;
        }

        let total_chars = entry.output.len();

        if offset >= total_chars {
            return Some(FetchResult {
                text: String::new(),
                total_chars,
                offset,
                has_more: false,
            });
        }

        // Find safe char boundaries for the slice
        let start = ceil_char_boundary(&entry.output, offset);
        let end_raw = start.saturating_add(limit).min(total_chars);
        let end = ceil_char_boundary(&entry.output, end_raw);

        let text = entry.output[start..end].to_string();
        let has_more = end < total_chars;

        Some(FetchResult {
            text,
            total_chars,
            offset: start,
            has_more,
        })
    }

    /// Remove all expired entries.
    pub async fn cleanup(&self) {
        let mut entries = self.entries.write().await;
        let now = Instant::now();
        entries.retain(|_, entry| now.duration_since(entry.created) < self.ttl);
    }

    /// Return the current number of cached entries.
    #[cfg(test)]
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Check if the cache is empty.
    #[cfg(test)]
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_store_and_fetch_round_trip() {
        let cache = OutputCache::new(300, 100);
        let id = cache.store("Hello, world!".to_string()).await;

        let result = cache.fetch(&id, 0, 100).await.unwrap();
        assert_eq!(result.text, "Hello, world!");
        assert_eq!(result.total_chars, 13);
        assert_eq!(result.offset, 0);
        assert!(!result.has_more);
    }

    #[tokio::test]
    async fn test_store_returns_sequential_ids() {
        let cache = OutputCache::new(300, 100);
        let id1 = cache.store("a".to_string()).await;
        let id2 = cache.store("b".to_string()).await;
        let id3 = cache.store("c".to_string()).await;

        assert_eq!(id1, "out-0000");
        assert_eq!(id2, "out-0001");
        assert_eq!(id3, "out-0002");
    }

    #[tokio::test]
    async fn test_fetch_with_offset_and_limit() {
        let cache = OutputCache::new(300, 100);
        let content = "AAAA_BBBB_CCCC_DDDD_EEEE";
        let id = cache.store(content.to_string()).await;

        // Fetch middle portion
        let result = cache.fetch(&id, 5, 9).await.unwrap();
        assert_eq!(result.text, "BBBB_CCCC");
        assert_eq!(result.offset, 5);
        assert!(result.has_more);

        // Fetch from the end
        let result = cache.fetch(&id, 20, 100).await.unwrap();
        assert_eq!(result.text, "EEEE");
        assert!(!result.has_more);
    }

    #[tokio::test]
    async fn test_fetch_offset_beyond_length() {
        let cache = OutputCache::new(300, 100);
        let id = cache.store("short".to_string()).await;

        let result = cache.fetch(&id, 100, 50).await.unwrap();
        assert_eq!(result.text, "");
        assert!(!result.has_more);
    }

    #[tokio::test]
    async fn test_fetch_nonexistent_id() {
        let cache = OutputCache::new(300, 100);
        let result = cache.fetch("out-9999", 0, 100).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_ttl_expiry() {
        // 0-second TTL = immediate expiry
        let cache = OutputCache::new(0, 100);
        let id = cache.store("ephemeral".to_string()).await;

        // Should be expired immediately
        let result = cache.fetch(&id, 0, 100).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_max_entries_eviction() {
        let cache = OutputCache::new(300, 3);

        let _id1 = cache.store("first".to_string()).await;
        let _id2 = cache.store("second".to_string()).await;
        let _id3 = cache.store("third".to_string()).await;
        assert_eq!(cache.len().await, 3);

        // Storing a 4th should evict the oldest
        let _id4 = cache.store("fourth".to_string()).await;
        assert_eq!(cache.len().await, 3);
    }

    #[tokio::test]
    async fn test_cleanup_removes_expired() {
        let cache = OutputCache::new(0, 100);
        cache.store("a".to_string()).await;
        cache.store("b".to_string()).await;

        cache.cleanup().await;
        assert_eq!(cache.len().await, 0);
    }

    #[tokio::test]
    async fn test_unicode_fetch_safe() {
        let cache = OutputCache::new(300, 100);
        let content = "日本語テスト🎉emoji";
        let id = cache.store(content.to_string()).await;

        // Fetch full content
        let result = cache.fetch(&id, 0, 1000).await.unwrap();
        assert_eq!(result.text, content);

        // Fetch with offset in the middle of multi-byte chars
        // Should safely align to char boundary
        let result = cache.fetch(&id, 1, 6).await.unwrap();
        // Offset 1 is inside "日" (3 bytes), should snap to byte 3 ("本")
        assert!(result.text.is_char_boundary(0));
    }

    #[tokio::test(start_paused = true)]
    async fn test_fetch_expired_at_exact_ttl_boundary() {
        // Strict `<` in the TTL checks: an entry whose age == ttl is expired.
        let cache = OutputCache::new(300, 100);
        let id = cache.store("x".to_string()).await;
        tokio::time::advance(Duration::from_secs(300)).await;
        assert!(cache.fetch(&id, 0, 10).await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn test_fetch_alive_just_before_ttl_boundary() {
        let cache = OutputCache::new(300, 100);
        let id = cache.store("x".to_string()).await;
        tokio::time::advance(Duration::from_secs(300) - Duration::from_millis(1)).await;
        assert!(cache.fetch(&id, 0, 10).await.is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn test_store_lazy_cleanup_evicts_at_exact_ttl() {
        let cache = OutputCache::new(300, 100);
        cache.store("old".to_string()).await;
        tokio::time::advance(Duration::from_secs(300)).await;
        cache.store("new".to_string()).await; // lazy cleanup runs here
        assert_eq!(cache.len().await, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_cleanup_evicts_at_exact_ttl() {
        let cache = OutputCache::new(300, 100);
        cache.store("a".to_string()).await;
        cache.store("b".to_string()).await;
        tokio::time::advance(Duration::from_secs(300)).await;
        cache.cleanup().await;
        assert!(cache.is_empty().await);
    }

    #[tokio::test]
    async fn test_concurrent_store_and_fetch() {
        use std::sync::Arc;

        let cache = Arc::new(OutputCache::new(300, 1000));

        let mut handles = Vec::new();
        for i in 0..50 {
            let cache = Arc::clone(&cache);
            handles.push(tokio::spawn(async move {
                let id = cache.store(format!("output-{i}")).await;
                let result = cache.fetch(&id, 0, 1000).await.unwrap();
                assert_eq!(result.text, format!("output-{i}"));
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }
    }
}
