//! All domain types shared across modules.
//!
//! Wire format: `GossipEnvelope` and all handshake messages use `bincode`.
//! API responses use `serde_json`.

use serde::{Deserialize, Serialize};

// ── Magic Byte Constants ──────────────────────────────────────────────────────

/// Identifies a HandshakeProbe message.
pub const HANDSHAKE_PROBE_MAGIC: &[u8] = b"WITAN_GOSSIP_HANDSHAKE_V1";

/// Identifies a HandshakeAck message.
pub const HANDSHAKE_ACK_MAGIC: &[u8] = b"WITAN_GOSSIP_HANDSHAKE_ACK_V1";

/// Identifies a HandshakeFinish message.
pub const HANDSHAKE_FINISH_MAGIC: &[u8] = b"WITAN_GOSSIP_HANDSHAKE_FINISH_V1";

/// Identifies a HandshakeFinishAck message.
pub const HANDSHAKE_FINISH_ACK_MAGIC: &[u8] = b"WITAN_GOSSIP_HANDSHAKE_FINISH_ACK_V1";

/// ML-DSA-65 context for handshake transcript signatures.
pub const SIG_CTX_HANDSHAKE: &[u8] = b"WITAN_GOSSIP_HANDSHAKE_V1";

/// ML-DSA-65 context for gossip envelope signatures.
pub const SIG_CTX_MESSAGE: &[u8] = b"WITAN_GOSSIP_MESSAGE_V1";

/// ML-DSA-65 context for node identity claims.
pub const SIG_CTX_NODE_ID: &[u8] = b"WITAN_NODE_IDENTITY_V1";

/// HKDF info string for session key derivation.
pub const HKDF_INFO_SESSION: &[u8] = b"pqc-kem-hybrid-v1";

// ── PayloadType ───────────────────────────────────────────────────────────────

/// Discriminant for the gossip message payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum PayloadType {
    /// Blockchain transaction. Gossip to all mesh peers.
    Transaction = 0,

    /// Block proposal from a validator. High priority.
    BlockProposal = 1,

    /// Finality vote from a validator. High priority.
    FinalityVote = 2,

    /// State synchronization data. May be large.
    StateSync = 3,

    /// Peer discovery advertisement. Contains PeerInfo JSON.
    PeerDiscovery = 4,
}

impl PayloadType {
    /// Convert a u8 discriminant to a PayloadType, returning None for unknown values.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Transaction),
            1 => Some(Self::BlockProposal),
            2 => Some(Self::FinalityVote),
            3 => Some(Self::StateSync),
            4 => Some(Self::PeerDiscovery),
            _ => None,
        }
    }

    /// Return the u8 discriminant value.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

// ── GossipEnvelope ────────────────────────────────────────────────────────────

/// The fundamental unit of gossip — a signed, typed message.
///
/// Wire format: bincode (compact, deterministic field order).
/// Field order is fixed and must not change without a version bump.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipEnvelope {
    /// Protocol version. Always 1 for this implementation.
    pub version: u8,

    /// SHA-256(payload_type_byte || payload). 32 bytes.
    pub message_id: [u8; 32],

    /// Node identity string. Format: SHA-256(kem_pk || sig_pk) as lowercase hex.
    pub sender_node_id: String,

    /// ML-DSA-65 public key of the sender. 1952 bytes.
    /// Used by recipients to verify the signature field.
    pub sender_public_key: Vec<u8>,

    /// Payload type discriminant. Maps to PayloadType enum.
    pub payload_type: PayloadType,

    /// Raw application payload bytes. Max 1MB (configurable).
    pub payload: Vec<u8>,

    /// ML-DSA-65 signature over signing_input().
    /// signing_input = message_id (32b) || payload_type_byte (1b) || payload
    /// Context string: b"WITAN_GOSSIP_MESSAGE_V1"
    /// Size: 3309 bytes.
    pub signature: Vec<u8>,

    /// Unix timestamp in milliseconds when the envelope was created.
    /// Used for replay protection: recipients reject if |now - timestamp| > 30s.
    pub timestamp_unix_ms: u64,

    /// Hop count limit. Decremented by each forwarding node.
    /// Default: 8. Message dropped when ttl reaches 0.
    pub ttl: u8,
}

// ── NodeIdentityPublic ────────────────────────────────────────────────────────

/// Public-only view of NodeIdentity, safe to serialize and send.
///
/// Wire format: JSON (API response only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentityPublic {
    /// Node identifier (64-char hex).
    pub node_id: String,

    /// HybridPublicKey serialized via HybridPublicKey::to_json().
    /// Contains X25519 and ML-KEM-768 public key components.
    pub kem_public_key_json: String,

    /// ML-DSA-65 public key as lowercase hex. 1952 bytes = 3904 hex chars.
    pub sig_public_key_hex: String,

    /// Key epoch label.
    pub key_epoch: String,
}

// ── PeerInfo ──────────────────────────────────────────────────────────────────

/// Public information about a connected peer.
///
/// Wire format: JSON (API response).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Network address (e.g. "192.168.1.10:9000" or "[::1]:9000").
    pub addr: String,

    /// Peer's node ID (64-char hex).
    pub node_id: String,

    /// Active session ID (64-char hex).
    pub session_id: String,

    /// Unix timestamp (ms) when the session was established.
    pub established_at_ms: u64,
}

// ── GossipStats ───────────────────────────────────────────────────────────────

/// Runtime statistics for the gossip component.
///
/// Wire format: JSON (API response).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GossipStats {
    /// Total envelopes published by this node (gossip_publish calls).
    pub messages_published: u64,

    /// Total envelopes received from peers (passed to verify_envelope).
    pub messages_received: u64,

    /// Total envelopes rejected as duplicates (already in dedup cache).
    pub messages_deduplicated: u64,

    /// Total envelopes dropped (TTL=0, replay, invalid sig, oversized).
    pub messages_dropped: u64,

    /// Number of currently active peer sessions.
    pub active_peers: u32,

    /// Number of peers currently in the gossip mesh (≤ mesh_n_high).
    pub mesh_peers: u32,

    /// Current size of the dedup cache (number of message IDs tracked).
    pub dedup_cache_size: u32,

    /// Total PQC handshakes completed successfully since init.
    pub handshakes_completed: u32,

    /// Total PQC handshakes that failed since init.
    pub handshakes_failed: u32,
}

// ── Handshake Message Types ───────────────────────────────────────────────────

/// Message 1: Client → Server
///
/// Initiates the handshake. Announces the client's identity and provides
/// a nonce for the session ID derivation.
///
/// Wire format: bincode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeProbe {
    /// Magic bytes to identify this as a handshake probe.
    /// Value: b"WITAN_GOSSIP_HANDSHAKE_V1" (25 bytes)
    pub magic: Vec<u8>,

    /// Protocol version. Always 1.
    pub version: u8,

    /// 32-byte random nonce generated by the client.
    /// Used in session ID derivation.
    pub client_nonce: [u8; 32],

    /// Client's network endpoint string (e.g. "192.168.1.5:9001").
    pub endpoint: String,

    /// Client's node ID (64-char hex).
    pub client_node_id: String,

    /// Unix timestamp (ms) when the probe was created.
    /// Server rejects if |now - timestamp| > 30s.
    pub timestamp_unix_ms: u64,
}

/// Message 2: Server → Client
///
/// Provides the server's KEM public key and ML-DSA-65 public key.
/// The client uses the KEM public key to encapsulate a shared secret.
///
/// Wire format: bincode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeAck {
    /// Magic bytes: b"WITAN_GOSSIP_HANDSHAKE_ACK_V1" (29 bytes)
    pub magic: Vec<u8>,

    /// Protocol version. Always 1.
    pub version: u8,

    /// Echo of the client's nonce (proves server received the probe).
    pub client_nonce: [u8; 32],

    /// 32-byte random nonce generated by the server.
    pub server_nonce: [u8; 32],

    /// Server's HybridPublicKey serialized via HybridPublicKey::to_json().
    /// Client uses this to encapsulate a shared secret.
    pub hybrid_kem_public_key_json: String,

    /// Server's ML-DSA-65 public key. 1952 bytes.
    pub ml_dsa_65_public_key: Vec<u8>,

    /// Server's node ID (64-char hex).
    pub server_node_id: String,

    /// Unix timestamp (ms).
    pub timestamp_unix_ms: u64,
}

/// Message 3: Client → Server
///
/// Encapsulates a shared secret to the server's KEM public key.
/// Provides the client's ML-DSA-65 public key for future envelope verification.
///
/// Wire format: bincode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeFinish {
    /// Magic bytes: b"WITAN_GOSSIP_HANDSHAKE_FINISH_V1" (32 bytes)
    pub magic: Vec<u8>,

    /// Protocol version. Always 1.
    pub version: u8,

    /// KEM ciphertext from HybridKemKeypair::encapsulate_to().
    /// Serialized via HybridKemCiphertext::to_json().
    pub kem_ciphertext_json: String,

    /// Client's ML-DSA-65 public key. 1952 bytes.
    pub client_ml_dsa_65_public_key: Vec<u8>,

    /// Client's node ID (64-char hex).
    pub client_node_id: String,

    /// Unix timestamp (ms).
    pub timestamp_unix_ms: u64,
}

/// Message 4: Server → Client
///
/// Proves the server successfully decapsulated the shared secret (via MAC).
/// Signs the full transcript with ML-DSA-65. Delivers the derived session ID.
///
/// Wire format: bincode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeFinishAck {
    /// Magic bytes: b"WITAN_GOSSIP_HANDSHAKE_FINISH_ACK_V1" (36 bytes)
    pub magic: Vec<u8>,

    /// Protocol version. Always 1.
    pub version: u8,

    /// Derived session ID (64-char hex).
    /// Computed via HKDF-SHA256 over shared_secret + nonces + ciphertext + node_id.
    pub session_id: String,

    /// SHA-256 of the full handshake transcript.
    /// transcript = probe_bytes || ack_bytes || finish_bytes
    pub transcript_hash: [u8; 32],

    /// HMAC-SHA256(shared_secret_32b, transcript_hash).
    /// Proves server holds the shared secret.
    pub server_mac: [u8; 32],

    /// ML-DSA-65 signature over transcript_hash.
    /// Context: b"WITAN_GOSSIP_HANDSHAKE_V1"
    /// Signed with server's sig_keypair.
    /// Size: 3309 bytes.
    pub transcript_signature: Vec<u8>,

    /// Unix timestamp (ms).
    pub timestamp_unix_ms: u64,
}

/// Classifies incoming bytes by their magic prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    HandshakeProbe,
    HandshakeAck,
    HandshakeFinish,
    HandshakeFinishAck,
    GossipEnvelope,
}

/// Classify incoming bytes by magic prefix for dispatch.
///
/// Bincode serializes `Vec<u8>` as `[u64 LE length][bytes...]`, so the first
/// 8 bytes of a bincode-encoded handshake message are the length of the magic
/// field. We skip those 8 bytes to find the actual magic bytes.
pub fn classify_incoming(bytes: &[u8]) -> MessageKind {
    // Bincode encodes Vec<u8> with an 8-byte little-endian length prefix.
    // All handshake messages start with `magic: Vec<u8>`, so skip 8 bytes.
    let payload = if bytes.len() > 8 { &bytes[8..] } else { bytes };

    // Check longest magic first to avoid prefix collisions
    // (HANDSHAKE_FINISH_ACK_MAGIC starts with HANDSHAKE_FINISH_MAGIC prefix)
    if payload.starts_with(HANDSHAKE_FINISH_ACK_MAGIC) {
        MessageKind::HandshakeFinishAck
    } else if payload.starts_with(HANDSHAKE_FINISH_MAGIC) {
        MessageKind::HandshakeFinish
    } else if payload.starts_with(HANDSHAKE_ACK_MAGIC) {
        MessageKind::HandshakeAck
    } else if payload.starts_with(HANDSHAKE_PROBE_MAGIC) {
        MessageKind::HandshakeProbe
    } else {
        MessageKind::GossipEnvelope
    }
}
