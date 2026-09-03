//! Top-level API functions that tie everything together.
//!
//! Uses `std::sync::OnceLock<Mutex<GossipEngine>>` for global singleton state.
//! WASM is single-threaded, so the mutex is never contended — it exists to
//! satisfy Rust's `Send` requirements for `static` bindings.

use std::sync::{Mutex, OnceLock};

use crate::config::GossipConfig;
use crate::error::GossipError;
use crate::gossip::GossipEngine;
use crate::identity::NodeIdentity;

// ── Global State ──────────────────────────────────────────────────────────────

static GOSSIP_STATE: OnceLock<Mutex<GossipEngine>> = OnceLock::new();

/// Acquire the global GossipEngine mutex guard.
///
/// Returns `GossipError::NotInitialized` if `gossip_init` has not been called.
fn with_engine<F, T>(f: F) -> Result<T, GossipError>
where
    F: FnOnce(&mut GossipEngine) -> Result<T, GossipError>,
{
    let mutex = GOSSIP_STATE
        .get()
        .ok_or(GossipError::NotInitialized)?;

    let mut engine = mutex
        .lock()
        .map_err(|e| GossipError::CryptoError(format!("mutex poisoned: {e}")))?;

    f(&mut engine)
}

// ── Time Abstraction ──────────────────────────────────────────────────────────

/// Get current Unix timestamp in milliseconds.
///
/// Uses `std::time::SystemTime` on every supported target. On `wasm32-wasip1`
/// and `wasm32-wasip2` the standard library backs this with the WASI wall
/// clock, so no target-specific branch is needed.
///
/// Note: `wasm32-unknown-unknown` is not a supported target — it has no WASI
/// clock, and `SystemTime::now()` would panic there at runtime.
pub fn current_time_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Initialize the gossip component with a JSON configuration.
///
/// Must be called exactly once before any other function.
/// Generates or restores node identity (KEM + SIG keypairs).
pub fn gossip_init(config_json: &str) -> Result<(), GossipError> {
    // Fail if already initialized
    if GOSSIP_STATE.get().is_some() {
        return Err(GossipError::AlreadyInitialized);
    }

    // Parse config
    let config = GossipConfig::from_json(config_json)?;
    let resolved = config.resolve()?;

    // Generate or restore identity
    let identity = if let (Some(kem_seed), Some(sig_seed)) =
        (&resolved.kem_seed, &resolved.sig_seed)
    {
        // Restore from seeds: kem_seed = 96 bytes (32 x25519 + 64 mlkem)
        let x25519_seed = &kem_seed[..32];
        let mlkem_seed = &kem_seed[32..96];
        NodeIdentity::from_seeds(x25519_seed, mlkem_seed, sig_seed, &resolved.key_epoch)?
    } else {
        NodeIdentity::generate(&resolved.key_epoch)?
    };

    let engine = GossipEngine::new(resolved, identity);

    // Store in global state (fails if already set — race condition guard)
    GOSSIP_STATE
        .set(Mutex::new(engine))
        .map_err(|_| GossipError::AlreadyInitialized)?;

    Ok(())
}

/// Publish a message to the gossip mesh.
///
/// Returns the 32-byte message ID.
pub fn gossip_publish(payload_type: u8, payload: &[u8]) -> Result<[u8; 32], GossipError> {
    let now_ms = current_time_unix_ms();
    with_engine(|engine| engine.publish(payload_type, payload, now_ms))
}

/// Initiate a PQC handshake with a peer.
///
/// Returns the probe bytes for the host to transmit.
/// The host must call `gossip_process_handshake_bytes` as responses arrive.
pub fn gossip_connect_peer(peer_addr: &str) -> Result<Vec<u8>, GossipError> {
    let now_ms = current_time_unix_ms();
    with_engine(|engine| engine.connect_peer(peer_addr, now_ms))
}

/// Disconnect from a peer and remove their session.
pub fn gossip_disconnect_peer(peer_addr: &str) -> Result<(), GossipError> {
    with_engine(|engine| engine.disconnect_peer(peer_addr))
}

/// Get the list of currently connected peers as a JSON array.
pub fn gossip_get_peers() -> Result<String, GossipError> {
    with_engine(|engine| engine.get_peers_json())
}

/// Get the node's public identity as a JSON object.
pub fn gossip_get_node_identity() -> Result<String, GossipError> {
    with_engine(|engine| engine.get_node_identity_json())
}

/// Verify a received GossipEnvelope (bincode-encoded bytes).
pub fn gossip_verify_envelope(envelope_bytes: &[u8]) -> Result<bool, GossipError> {
    let now_ms = current_time_unix_ms();
    with_engine(|engine| engine.verify_envelope_bytes(envelope_bytes, now_ms))
}

/// Encode a new signed GossipEnvelope to bincode bytes.
pub fn gossip_encode_envelope(payload_type: u8, payload: &[u8]) -> Result<Vec<u8>, GossipError> {
    let now_ms = current_time_unix_ms();
    with_engine(|engine| engine.encode_envelope(payload_type, payload, now_ms))
}

/// Decode a GossipEnvelope from bincode bytes to a JSON string.
pub fn gossip_decode_envelope(bytes: &[u8]) -> Result<String, GossipError> {
    with_engine(|engine| engine.decode_envelope_to_json(bytes))
}

/// Get runtime statistics as a JSON object.
pub fn gossip_get_stats() -> Result<String, GossipError> {
    let now_ms = current_time_unix_ms();
    with_engine(|engine| {
        engine.heartbeat(now_ms);
        engine.get_stats_json(now_ms)
    })
}

/// Process incoming handshake bytes from a peer.
///
/// Returns optional response bytes to send back, or None if no response needed.
pub fn gossip_process_handshake_bytes(
    peer_addr: &str,
    bytes: &[u8],
) -> Result<Option<Vec<u8>>, GossipError> {
    let now_ms = current_time_unix_ms();
    with_engine(|engine| engine.process_handshake_bytes(peer_addr, bytes, now_ms))
}

/// Build the server-side handshake ACK (step 2 of 4).
///
/// Called by a node acting as server when it receives a probe.
/// Returns the ACK bytes to send back to the client.
pub fn gossip_build_handshake_ack(
    peer_addr: &str,
    probe_bytes: &[u8],
) -> Result<Vec<u8>, GossipError> {
    let now_ms = current_time_unix_ms();
    with_engine(|engine| {
        engine
            .handshakes
            .process_probe_build_ack(peer_addr, probe_bytes, &engine.identity, now_ms)
    })
}

/// Build the server-side finish ACK (step 4 of 4).
///
/// Called by a node acting as server when it receives the finish probe.
/// Returns the finish ACK bytes and completes the session.
pub fn gossip_build_finish_ack(
    peer_addr: &str,
    finish_bytes: &[u8],
) -> Result<Vec<u8>, GossipError> {
    let now_ms = current_time_unix_ms();
    with_engine(|engine| {
        let identity = engine.identity.clone();
        let (finish_ack_bytes, session) = engine.handshakes.process_finish_build_finish_ack(
            peer_addr,
            finish_bytes,
            &identity,
            now_ms,
        )?;
        engine.sessions.insert(session);
        engine.stats.handshakes_completed += 1;
        engine.stats.active_peers = engine.sessions.count() as u32;
        Ok(finish_ack_bytes)
    })
}

/// Get session info for a peer as JSON.
pub fn gossip_get_session(peer_addr: &str) -> Result<String, GossipError> {
    with_engine(|engine| engine.get_session_json(peer_addr))
}

/// Rotate node identity keys. Returns new node_id hex string.
pub fn gossip_rotate_keys() -> Result<String, GossipError> {
    with_engine(|engine| {
        let key_epoch = engine.config.key_epoch.clone();
        engine.rotate_keys(&key_epoch)
    })
}

/// Get the current Unix timestamp in milliseconds.
pub fn gossip_now_ms() -> u64 {
    current_time_unix_ms()
}

/// Verify a standalone ML-DSA-65 signature.
pub fn gossip_verify_signature(
    public_key_bytes: &[u8],
    message: &[u8],
    signature: &[u8],
    context: &[u8],
) -> Result<bool, GossipError> {
    GossipEngine::verify_signature(public_key_bytes, message, signature, context)
}

/// Get the component version string.
pub fn gossip_get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
