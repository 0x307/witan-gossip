//! SHA-256 message deduplication cache with TTL eviction.
//!
//! Stores `message_id -> insertion_timestamp_ms`. Expired entries are lazily
//! evicted on each `is_duplicate` or `insert` call.

use std::collections::HashMap;

/// Deduplication cache keyed by 32-byte message ID.
pub struct DedupCache {
    /// message_id -> insertion_timestamp_ms
    entries: HashMap<[u8; 32], u64>,
    /// TTL in milliseconds
    ttl_ms: u64,
}

impl DedupCache {
    /// Create a new dedup cache with the given TTL in seconds.
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            entries: HashMap::new(),
            ttl_ms: ttl_secs * 1000,
        }
    }

    /// Returns true if the message_id is already in the cache (not expired).
    ///
    /// Also evicts expired entries on each call (lazy eviction).
    pub fn is_duplicate(&mut self, message_id: &[u8; 32], now_ms: u64) -> bool {
        self.evict_expired(now_ms);
        self.entries.contains_key(message_id)
    }

    /// Insert a message_id into the cache with the current timestamp.
    pub fn insert(&mut self, message_id: [u8; 32], now_ms: u64) {
        self.entries.insert(message_id, now_ms);
    }

    /// Evict all entries where `now_ms - insertion_ms > ttl_ms`.
    pub fn evict_expired(&mut self, now_ms: u64) {
        self.entries
            .retain(|_, ts| now_ms.saturating_sub(*ts) <= self.ttl_ms);
    }

    /// Current number of entries in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return all active message IDs (for quorum tracker pruning).
    pub fn active_ids(&self) -> Vec<[u8; 32]> {
        self.entries.keys().copied().collect()
    }
}
