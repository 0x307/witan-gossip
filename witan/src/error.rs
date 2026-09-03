//! Unified error type for all gossip operations.

use serde::{Deserialize, Serialize};

/// All errors that can occur in the gossip component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipError {
    /// gossip_init has not been called yet.
    NotInitialized,

    /// gossip_init was called more than once.
    AlreadyInitialized,

    /// Config JSON parse error or invalid field value.
    ConfigError(String),

    /// Key generation or seed parsing failed.
    IdentityError(String),

    /// Handshake protocol violation or timeout.
    HandshakeError(String),

    /// No active session for the given peer address.
    SessionNotFound(String),

    /// Envelope field validation, encode, or decode error.
    EnvelopeError(String),

    /// ML-DSA-65 signature verification returned false.
    SignatureInvalid,

    /// Message timestamp outside ±replay_window_ms.
    ReplayDetected,

    /// Envelope TTL reached 0.
    TtlExpired,

    /// Peer address not in active session store.
    PeerNotFound(String),

    /// BFT quorum not yet reached for a message.
    QuorumNotReached,

    /// bincode or serde_json error.
    SerializationError(String),

    /// pqc_kem or pqc_sig returned an error.
    CryptoError(String),

    /// Invalid function argument (e.g. unknown payload_type_id).
    InvalidInput(String),
}

impl std::fmt::Display for GossipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GossipError::NotInitialized => write!(f, "gossip component not initialized"),
            GossipError::AlreadyInitialized => write!(f, "gossip component already initialized"),
            GossipError::ConfigError(s) => write!(f, "config error: {s}"),
            GossipError::IdentityError(s) => write!(f, "identity error: {s}"),
            GossipError::HandshakeError(s) => write!(f, "handshake error: {s}"),
            GossipError::SessionNotFound(s) => write!(f, "session not found: {s}"),
            GossipError::EnvelopeError(s) => write!(f, "envelope error: {s}"),
            GossipError::SignatureInvalid => write!(f, "signature verification failed"),
            GossipError::ReplayDetected => write!(f, "replay detected: message outside replay window"),
            GossipError::TtlExpired => write!(f, "TTL expired"),
            GossipError::PeerNotFound(s) => write!(f, "peer not found: {s}"),
            GossipError::QuorumNotReached => write!(f, "quorum not reached"),
            GossipError::SerializationError(s) => write!(f, "serialization error: {s}"),
            GossipError::CryptoError(s) => write!(f, "crypto error: {s}"),
            GossipError::InvalidInput(s) => write!(f, "invalid input: {s}"),
        }
    }
}

impl std::error::Error for GossipError {}
