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
use crate::rotation::{key_commitment_for_seed, KeyLineage};

// ── Global State ──────────────────────────────────────────────────────────────

static GOSSIP_STATE: OnceLock<Mutex<GossipEngine>> = OnceLock::new();

/// This node's key lineage. Kept beside the engine rather than in it so that
/// `GossipEngine`'s public field set is unchanged. Lock order: engine, then
/// lineage.
static LINEAGE: Mutex<Option<KeyLineage>> = Mutex::new(None);

fn with_lineage<F, T>(f: F) -> Result<T, GossipError>
where
    F: FnOnce(&mut Option<KeyLineage>) -> Result<T, GossipError>,
{
    let mut guard = LINEAGE
        .lock()
        .map_err(|e| GossipError::CryptoError(format!("mutex poisoned: {e}")))?;
    f(&mut guard)
}

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

    let lineage = KeyLineage::from_identity(&identity)?;
    install(resolved, identity, lineage)
}

/// Initialize a node that has rotated keys under a stable id.
///
/// `config_json` must carry `kem_seed_hex` and `sig_seed_hex` for the node's
/// **current** keys. `lineage_bytes` is the node's encoded [`KeyLineage`]
/// (from [`gossip_get_key_lineage`]); it is verified, and its current keys
/// must be the ones the seeds produce. The node then runs under the lineage's
/// stable id.
pub fn gossip_init_with_lineage(config_json: &str, lineage_bytes: &[u8]) -> Result<(), GossipError> {
    if GOSSIP_STATE.get().is_some() {
        return Err(GossipError::AlreadyInitialized);
    }

    let resolved = GossipConfig::from_json(config_json)?.resolve()?;
    let (Some(kem_seed), Some(sig_seed)) = (&resolved.kem_seed, &resolved.sig_seed) else {
        return Err(GossipError::ConfigError(
            "gossip_init_with_lineage needs kem_seed_hex and sig_seed_hex for the current keys"
                .to_string(),
        ));
    };
    let mut identity =
        NodeIdentity::from_seeds(&kem_seed[..32], &kem_seed[32..96], sig_seed, &resolved.key_epoch)?;

    let lineage = KeyLineage::decode(lineage_bytes)?;
    if identity.sig_public_key_bytes() != lineage.current_sig_public_key()
        || identity.kem_public_key_canonical_bytes()? != lineage.current_kem_public_key()
    {
        return Err(GossipError::IdentityError(format!(
            "seeds are not the current keys of lineage {} (sequence {})",
            lineage.node_id(),
            lineage.sequence()
        )));
    }
    identity.node_id = lineage.node_id().to_string();
    install(resolved, identity, lineage)
}

fn install(
    resolved: crate::config::ResolvedConfig,
    identity: NodeIdentity,
    lineage: KeyLineage,
) -> Result<(), GossipError> {
    let engine = GossipEngine::new(resolved, identity);

    // Store in global state (fails if already set — race condition guard)
    GOSSIP_STATE
        .set(Mutex::new(engine))
        .map_err(|_| GossipError::AlreadyInitialized)?;

    with_lineage(|l| {
        *l = Some(lineage);
        Ok(())
    })
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
///
/// The new keys get a new id and start a new lineage. To keep the id, use
/// [`gossip_rotate_keys_under_id`].
pub fn gossip_rotate_keys() -> Result<String, GossipError> {
    with_engine(|engine| {
        let key_epoch = engine.config.key_epoch.clone();
        let node_id = engine.rotate_keys(&key_epoch)?;
        let lineage = KeyLineage::from_identity(&engine.identity)?;
        with_lineage(|l| {
            *l = Some(lineage);
            Ok(node_id)
        })
    })
}

/// Rotate to the keys `kem_seed` (96 bytes) and `sig_seed` (32 bytes) produce,
/// keeping this node's id. Returns the updated encoded lineage, which the host
/// must persist (it is needed to restart, see [`gossip_init_with_lineage`])
/// and distribute to peers that pin this node.
///
/// `next_key_commitment` (32 bytes, from [`gossip_key_commitment`]) pins the
/// key the following rotation must use. If the current state already carries
/// a commitment, `sig_seed` must produce the committed key.
pub fn gossip_rotate_keys_under_id(
    kem_seed: &[u8],
    sig_seed: &[u8],
    key_epoch: &str,
    next_key_commitment: Option<&[u8]>,
) -> Result<Vec<u8>, GossipError> {
    let next = identity_from_seed_bytes(kem_seed, sig_seed, key_epoch)?;
    let commitment = parse_commitment(next_key_commitment)?;
    let now_ms = current_time_unix_ms();
    with_engine(|engine| {
        with_lineage(|l| {
            let lineage = l.as_mut().ok_or(GossipError::NotInitialized)?;
            // Work on a copy so a failed rotation leaves the stored lineage intact.
            let mut updated = lineage.clone();
            engine.rotate_keys_under_id(&mut updated, next, commitment, now_ms)?;
            let bytes = updated.encode()?;
            *lineage = updated;
            Ok(bytes)
        })
    })
}

/// Extend `lineage_bytes` to the pre-committed keys without the current key,
/// for a node whose current key is lost or compromised. Returns the extended
/// lineage; initialize the node with it via [`gossip_init_with_lineage`].
/// Stateless: needs no `gossip_init`.
pub fn gossip_recover_lineage(
    lineage_bytes: &[u8],
    kem_seed: &[u8],
    sig_seed: &[u8],
    key_epoch: &str,
    next_key_commitment: Option<&[u8]>,
) -> Result<Vec<u8>, GossipError> {
    let mut lineage = KeyLineage::decode(lineage_bytes)?;
    let next = identity_from_seed_bytes(kem_seed, sig_seed, key_epoch)?;
    lineage.recover(&next, parse_commitment(next_key_commitment)?, current_time_unix_ms())?;
    lineage.encode()
}

/// Get this node's encoded key lineage.
pub fn gossip_get_key_lineage() -> Result<Vec<u8>, GossipError> {
    with_lineage(|l| l.as_ref().ok_or(GossipError::NotInitialized)?.encode())
}

/// Verify an encoded key lineage and summarize its current state as JSON:
/// `{"node_id", "sequence", "sig_public_key_hex", "kem_public_key_hex",
/// "key_epoch", "next_key_commitment_hex"}` (the last is null when unset).
/// Stateless: needs no `gossip_init`.
pub fn gossip_verify_key_lineage(lineage_bytes: &[u8]) -> Result<String, GossipError> {
    let lineage = KeyLineage::decode(lineage_bytes)?;
    let summary = serde_json::json!({
        "node_id": lineage.node_id(),
        "sequence": lineage.sequence(),
        "sig_public_key_hex": hex::encode(lineage.current_sig_public_key()),
        "kem_public_key_hex": hex::encode(lineage.current_kem_public_key()),
        "key_epoch": lineage.current_key_epoch(),
        "next_key_commitment_hex": lineage.next_key_commitment().map(hex::encode),
    });
    serde_json::to_string(&summary)
        .map_err(|e| GossipError::SerializationError(format!("JSON serialize: {e}")))
}

/// Verify an envelope as [`gossip_verify_envelope`] does, and also require
/// that its sender is the lineage's node speaking with its current key.
pub fn gossip_verify_envelope_from_lineage(
    envelope_bytes: &[u8],
    lineage_bytes: &[u8],
) -> Result<bool, GossipError> {
    let lineage = KeyLineage::decode(lineage_bytes)?;
    let now_ms = current_time_unix_ms();
    with_engine(|engine| {
        let envelope = crate::envelope::decode_envelope(envelope_bytes)?;
        if let Err(e) = lineage.check_envelope_sender(&envelope) {
            engine.stats.messages_dropped += 1;
            return Err(e);
        }
        engine.verify_envelope_bytes(envelope_bytes, now_ms)
    })
}

/// Pre-rotation commitment to the signing key `sig_seed` (32 bytes) produces.
/// Stateless: needs no `gossip_init`.
pub fn gossip_key_commitment(sig_seed: &[u8]) -> Result<Vec<u8>, GossipError> {
    key_commitment_for_seed(sig_seed).map(|c| c.to_vec())
}

fn identity_from_seed_bytes(
    kem_seed: &[u8],
    sig_seed: &[u8],
    key_epoch: &str,
) -> Result<NodeIdentity, GossipError> {
    if kem_seed.len() != 96 {
        return Err(GossipError::InvalidInput(format!(
            "kem_seed must be 96 bytes, got {}",
            kem_seed.len()
        )));
    }
    if sig_seed.len() != 32 {
        return Err(GossipError::InvalidInput(format!(
            "sig_seed must be 32 bytes, got {}",
            sig_seed.len()
        )));
    }
    NodeIdentity::from_seeds(&kem_seed[..32], &kem_seed[32..], sig_seed, key_epoch)
}

fn parse_commitment(c: Option<&[u8]>) -> Result<Option<[u8; 32]>, GossipError> {
    c.map(|b| {
        b.try_into().map_err(|_| {
            GossipError::InvalidInput(format!(
                "next_key_commitment must be 32 bytes, got {}",
                b.len()
            ))
        })
    })
    .transpose()
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
