//! BFT quorum tracker.
//!
//! Tracks which peers have acknowledged each message.
//! A message reaches quorum when `ack_count >= ceil(total_peers * quorum_fraction)`.

use std::collections::{HashMap, HashSet};

/// BFT quorum tracker.
///
/// Tracks acknowledgements per message_id. Quorum is reached when
/// `ack_count >= ceil(total_peers * quorum_fraction)`.
pub struct QuorumTracker {
    /// message_id -> set of peer_addrs that acknowledged
    acks: HashMap<[u8; 32], HashSet<String>>,
    /// Fraction of peers required for quorum (e.g. 0.67 for ≥2/3)
    quorum_fraction: f64,
}

impl QuorumTracker {
    /// Create a new quorum tracker with the given fraction.
    pub fn new(quorum_fraction: f64) -> Self {
        Self {
            acks: HashMap::new(),
            quorum_fraction,
        }
    }

    /// Record that a peer acknowledged a message.
    pub fn record_ack(&mut self, message_id: &[u8; 32], peer_addr: &str) {
        self.acks
            .entry(*message_id)
            .or_insert_with(HashSet::new)
            .insert(peer_addr.to_string());
    }

    /// Check if quorum is reached given total known peers.
    ///
    /// Returns false if total_peers == 0.
    pub fn has_quorum(&self, message_id: &[u8; 32], total_peers: usize) -> bool {
        if total_peers == 0 {
            return false;
        }
        let required = (total_peers as f64 * self.quorum_fraction).ceil() as usize;
        let ack_count = self.acks.get(message_id).map(|s| s.len()).unwrap_or(0);
        ack_count >= required
    }

    /// Get the ack count for a message.
    pub fn ack_count(&self, message_id: &[u8; 32]) -> usize {
        self.acks.get(message_id).map(|s| s.len()).unwrap_or(0)
    }

    /// Prune entries for message IDs no longer in the dedup cache.
    pub fn prune(&mut self, known_message_ids: &[[u8; 32]]) {
        let known: HashSet<[u8; 32]> = known_message_ids.iter().copied().collect();
        self.acks.retain(|id, _| known.contains(id));
    }
}
