//! WASM Component Model export layer.
//!
//! This module implements the `witan:gossip/gossip-world` world defined in
//! [`wit/gossip-protocol.wit`](../wit/gossip-protocol.wit). Bindings are
//! generated at compile time by `wit-bindgen`; each exported function is a thin
//! delegation to the corresponding function in [`crate::api`].
//!
//! There is deliberately no marshaling code here. The Component Model moves
//! `list<u8>` and `string` across the boundary itself, so the allocator
//! plumbing and out-slot conventions required by the legacy C-ABI
//! ([`crate::wasi_exports`], behind the deprecated `wasi-abi` feature) have no
//! equivalent on this path.
//!
//! Built for `wasm32-wasip2`, where the Rust standard library supplies the WASI
//! clock and entropy imports that `api::current_time_unix_ms` and `OsRng`
//! depend on.

wit_bindgen::generate!({
    world: "gossip-world",
    path: "wit",
});

use exports::witan::gossip::gossip_protocol::{Guest, GossipError as WitError};

use crate::api;
use crate::error::GossipError;

/// The component instance. Zero-sized: all state lives in the `api` module's
/// process-global engine, exactly as it does for native and legacy-ABI callers.
struct WitanGossip;

// ── Error mapping ─────────────────────────────────────────────────────────────

impl From<GossipError> for WitError {
    fn from(e: GossipError) -> Self {
        match e {
            GossipError::NotInitialized => WitError::NotInitialized,
            GossipError::AlreadyInitialized => WitError::AlreadyInitialized,
            GossipError::ConfigError(s) => WitError::ConfigError(s),
            GossipError::IdentityError(s) => WitError::IdentityError(s),
            GossipError::HandshakeError(s) => WitError::HandshakeError(s),
            GossipError::SessionNotFound(s) => WitError::SessionNotFound(s),
            GossipError::EnvelopeError(s) => WitError::EnvelopeError(s),
            GossipError::SignatureInvalid => WitError::SignatureInvalid,
            GossipError::ReplayDetected => WitError::ReplayDetected,
            GossipError::TtlExpired => WitError::TtlExpired,
            GossipError::PeerNotFound(s) => WitError::PeerNotFound(s),
            GossipError::QuorumNotReached => WitError::QuorumNotReached,
            GossipError::SerializationError(s) => WitError::SerializationError(s),
            GossipError::CryptoError(s) => WitError::CryptoError(s),
            GossipError::InvalidInput(s) => WitError::InvalidInput(s),
        }
    }
}

// ── Exported interface ────────────────────────────────────────────────────────

impl Guest for WitanGossip {
    fn gossip_init(config_json: String) -> Result<(), WitError> {
        api::gossip_init(&config_json).map_err(Into::into)
    }

    fn gossip_publish(payload_type_id: u8, payload: Vec<u8>) -> Result<Vec<u8>, WitError> {
        api::gossip_publish(payload_type_id, &payload)
            .map(|id| id.to_vec())
            .map_err(Into::into)
    }

    fn gossip_connect_peer(peer_addr: String) -> Result<Vec<u8>, WitError> {
        api::gossip_connect_peer(&peer_addr).map_err(Into::into)
    }

    fn gossip_disconnect_peer(peer_addr: String) -> Result<(), WitError> {
        api::gossip_disconnect_peer(&peer_addr).map_err(Into::into)
    }

    fn gossip_get_peers() -> Result<String, WitError> {
        api::gossip_get_peers().map_err(Into::into)
    }

    fn gossip_get_session(peer_addr: String) -> Result<String, WitError> {
        api::gossip_get_session(&peer_addr).map_err(Into::into)
    }

    fn gossip_get_node_identity() -> Result<String, WitError> {
        api::gossip_get_node_identity().map_err(Into::into)
    }

    fn gossip_rotate_keys() -> Result<String, WitError> {
        api::gossip_rotate_keys().map_err(Into::into)
    }

    fn gossip_verify_envelope(envelope_bytes: Vec<u8>) -> Result<bool, WitError> {
        api::gossip_verify_envelope(&envelope_bytes).map_err(Into::into)
    }

    fn gossip_encode_envelope(payload_type_id: u8, payload: Vec<u8>) -> Result<Vec<u8>, WitError> {
        api::gossip_encode_envelope(payload_type_id, &payload).map_err(Into::into)
    }

    fn gossip_decode_envelope(bytes: Vec<u8>) -> Result<String, WitError> {
        api::gossip_decode_envelope(&bytes).map_err(Into::into)
    }

    fn gossip_get_stats() -> Result<String, WitError> {
        api::gossip_get_stats().map_err(Into::into)
    }

    fn gossip_process_handshake_bytes(
        peer_addr: String,
        bytes: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, WitError> {
        api::gossip_process_handshake_bytes(&peer_addr, &bytes).map_err(Into::into)
    }

    fn gossip_build_handshake_ack(
        peer_addr: String,
        probe_bytes: Vec<u8>,
    ) -> Result<Vec<u8>, WitError> {
        api::gossip_build_handshake_ack(&peer_addr, &probe_bytes).map_err(Into::into)
    }

    fn gossip_build_finish_ack(
        peer_addr: String,
        finish_bytes: Vec<u8>,
    ) -> Result<Vec<u8>, WitError> {
        api::gossip_build_finish_ack(&peer_addr, &finish_bytes).map_err(Into::into)
    }

    fn gossip_now_ms() -> u64 {
        api::gossip_now_ms()
    }

    fn gossip_verify_signature(
        public_key_bytes: Vec<u8>,
        message: Vec<u8>,
        signature: Vec<u8>,
        context: Vec<u8>,
    ) -> Result<bool, WitError> {
        api::gossip_verify_signature(&public_key_bytes, &message, &signature, &context)
            .map_err(Into::into)
    }

    fn gossip_get_version() -> String {
        api::gossip_get_version()
    }
}

export!(WitanGossip);
