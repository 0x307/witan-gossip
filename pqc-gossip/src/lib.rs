//! # witan-gossip
//!
//! Post-Quantum Cryptography Gossip Protocol WASM Component for the blockchain runtime.
//!
//! ## Architecture
//!
//! This crate implements a production-grade PQC gossip protocol as a WASM Component
//! Model component. The blockchain host owns transport (QUIC/TCP/WebTransport).
//! This component owns all cryptographic and protocol logic.
//!
//! ## Module Structure
//!
//! - [`api`] — Top-level API functions (global singleton state)
//! - [`config`] — GossipConfig deserialization and validation
//! - [`dedup`] — SHA-256 message deduplication cache with TTL eviction
//! - [`envelope`] — GossipEnvelope encode/decode/sign/verify
//! - [`error`] — GossipError unified error type
//! - [`gossip`] — GossipEngine central state machine
//! - [`handshake`] — PQC 4-message handshake state machine
//! - [`identity`] — NodeIdentity generation and management
//! - [`quorum`] — BFT quorum tracker (≥2/3 peers)
//! - [`session`] — SessionStore and session ID derivation
//! - [`types`] — All domain types (GossipEnvelope, PayloadType, etc.)

#[cfg(target_arch = "wasm32")]
pub mod wasi_exports;

pub mod api;
pub mod config;
pub mod dedup;
pub mod envelope;
pub mod error;
pub mod gossip;
pub mod handshake;
pub mod identity;
pub mod quorum;
pub mod session;
pub mod types;

// ── Public Re-exports ─────────────────────────────────────────────────────────

pub use api::{
    current_time_unix_ms,
    gossip_build_finish_ack,
    gossip_build_handshake_ack,
    gossip_connect_peer,
    gossip_decode_envelope,
    gossip_disconnect_peer,
    gossip_encode_envelope,
    gossip_get_node_identity,
    gossip_get_peers,
    gossip_get_session,
    gossip_get_stats,
    gossip_get_version,
    gossip_init,
    gossip_now_ms,
    gossip_process_handshake_bytes,
    gossip_publish,
    gossip_rotate_keys,
    gossip_verify_envelope,
    gossip_verify_signature,
};

pub use config::GossipConfig;
pub use error::GossipError;
pub use types::{
    GossipEnvelope, GossipStats, HandshakeAck, HandshakeFinish, HandshakeFinishAck,
    HandshakeProbe, MessageKind, NodeIdentityPublic, PayloadType, PeerInfo,
    HANDSHAKE_ACK_MAGIC, HANDSHAKE_FINISH_ACK_MAGIC, HANDSHAKE_FINISH_MAGIC,
    HANDSHAKE_PROBE_MAGIC, HKDF_INFO_SESSION, SIG_CTX_HANDSHAKE, SIG_CTX_MESSAGE,
    SIG_CTX_NODE_ID,
};
