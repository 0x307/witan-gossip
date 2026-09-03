//! Session store and session ID derivation.
//!
//! `SessionRecord` is stored in memory only — never serialized to wire.
//! `SessionStore` is keyed by peer_addr.

use std::collections::HashMap;

use hkdf::Hkdf;
use sha2::Sha256;

use crate::types::{PeerInfo, HKDF_INFO_SESSION};

/// A completed handshake session record.
///
/// Stored in memory only. Not serialized to wire.
#[derive(Debug, Clone)]
pub struct SessionRecord {
    /// Derived session ID (64-char hex).
    pub session_id: String,

    /// Peer's network address.
    pub peer_addr: String,

    /// Peer's node ID (64-char hex).
    pub peer_node_id: String,

    /// Peer's ML-DSA-65 public key (1952 bytes).
    /// Cached for envelope verification without re-handshaking.
    pub peer_sig_public_key: Vec<u8>,

    /// SHA-256 of the handshake transcript.
    pub transcript_hash: [u8; 32],

    /// Unix timestamp (ms) when the session was established.
    pub established_at_ms: u64,

    /// Whether the session is currently active.
    pub is_active: bool,
}

/// In-memory store for active peer sessions.
///
/// Keyed by peer_addr string.
pub struct SessionStore {
    sessions: HashMap<String, SessionRecord>,
}

impl SessionStore {
    /// Create a new empty session store.
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Insert or replace a session record.
    pub fn insert(&mut self, record: SessionRecord) {
        self.sessions.insert(record.peer_addr.clone(), record);
    }

    /// Get a session by peer address.
    pub fn get(&self, peer_addr: &str) -> Option<&SessionRecord> {
        self.sessions.get(peer_addr)
    }

    /// Remove a session by peer address.
    pub fn remove(&mut self, peer_addr: &str) -> Option<SessionRecord> {
        self.sessions.remove(peer_addr)
    }

    /// Get all active peer infos (for API responses).
    pub fn active_peers(&self) -> Vec<PeerInfo> {
        self.sessions
            .values()
            .filter(|s| s.is_active)
            .map(|s| PeerInfo {
                addr: s.peer_addr.clone(),
                node_id: s.peer_node_id.clone(),
                session_id: s.session_id.clone(),
                established_at_ms: s.established_at_ms,
            })
            .collect()
    }

    /// Count of all sessions (active or not).
    pub fn count(&self) -> usize {
        self.sessions.len()
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Derive session ID using HKDF-SHA256.
///
/// IKM = shared_secret_32b || client_nonce_32b || server_nonce_32b
///       || kem_ciphertext_bytes || node_id_bytes
/// info = b"pqc-kem-hybrid-v1"
/// output = 32 bytes, hex-encoded (64 chars)
pub fn derive_session_id(
    shared_secret_32b: &[u8; 32],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    kem_ciphertext_bytes: &[u8],
    node_id: &str,
) -> String {
    let mut ikm = Vec::with_capacity(32 + 32 + 32 + kem_ciphertext_bytes.len() + node_id.len());
    ikm.extend_from_slice(shared_secret_32b);
    ikm.extend_from_slice(client_nonce);
    ikm.extend_from_slice(server_nonce);
    ikm.extend_from_slice(kem_ciphertext_bytes);
    ikm.extend_from_slice(node_id.as_bytes());

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO_SESSION, &mut okm)
        .expect("HKDF expand: 32 bytes always fits");

    hex::encode(okm)
}

/// Compute the transcript hash: SHA-256(probe_bytes || ack_bytes || finish_bytes).
pub fn compute_transcript_hash(
    probe_bytes: &[u8],
    ack_bytes: &[u8],
    finish_bytes: &[u8],
) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(probe_bytes);
    hasher.update(ack_bytes);
    hasher.update(finish_bytes);
    hasher.finalize().into()
}

/// Compute the server MAC: HMAC-SHA256(shared_secret_32b, transcript_hash).
pub fn compute_server_mac(shared_secret_32b: &[u8; 32], transcript_hash: &[u8; 32]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(shared_secret_32b)
        .expect("HMAC accepts any key size");
    mac.update(transcript_hash);
    mac.finalize().into_bytes().into()
}
