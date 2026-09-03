//! GossipEnvelope encoding, decoding, signing, and verification.

use sha2::{Digest, Sha256};

use crate::config::ResolvedConfig;
use crate::error::GossipError;
use crate::identity::NodeIdentity;
use crate::types::{GossipEnvelope, PayloadType, SIG_CTX_MESSAGE};

/// Compute message_id = SHA-256(payload_type_byte || payload).
pub fn compute_message_id(payload_type: PayloadType, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([payload_type.as_u8()]);
    hasher.update(payload);
    hasher.finalize().into()
}

/// Compute the bytes that are signed:
/// signing_input = message_id (32b) || payload_type_byte (1b) || payload
pub fn signing_input(env: &GossipEnvelope) -> Vec<u8> {
    let mut input = Vec::with_capacity(32 + 1 + env.payload.len());
    input.extend_from_slice(&env.message_id);
    input.push(env.payload_type.as_u8());
    input.extend_from_slice(&env.payload);
    input
}

/// Build and sign a new GossipEnvelope.
pub fn build_envelope(
    payload_type: PayloadType,
    payload: &[u8],
    identity: &NodeIdentity,
    default_ttl: u8,
    now_ms: u64,
) -> Result<GossipEnvelope, GossipError> {
    let message_id = compute_message_id(payload_type, payload);

    // Build the envelope (without signature first)
    let mut env = GossipEnvelope {
        version: 1,
        message_id,
        sender_node_id: identity.node_id.clone(),
        sender_public_key: identity.sig_public_key_bytes(),
        payload_type,
        payload: payload.to_vec(),
        signature: Vec::new(), // filled below
        timestamp_unix_ms: now_ms,
        ttl: default_ttl,
    };

    // Compute signing input and sign
    let input = signing_input(&env);
    let signature = identity.sign(&input, SIG_CTX_MESSAGE)?;
    env.signature = signature;

    Ok(env)
}

/// Encode GossipEnvelope to bincode bytes.
pub fn encode_envelope(env: &GossipEnvelope) -> Result<Vec<u8>, GossipError> {
    bincode::serialize(env)
        .map_err(|e| GossipError::SerializationError(format!("bincode encode failed: {e}")))
}

/// Decode GossipEnvelope from bincode bytes.
pub fn decode_envelope(bytes: &[u8]) -> Result<GossipEnvelope, GossipError> {
    bincode::deserialize(bytes)
        .map_err(|e| GossipError::SerializationError(format!("bincode decode failed: {e}")))
}

/// Verify envelope signature and replay window.
///
/// Checks:
/// 1. version == 1
/// 2. message_id == SHA-256(payload_type_byte || payload)
/// 3. |now_ms - timestamp_unix_ms| <= replay_window_ms
/// 4. ttl > 0
/// 5. payload.len() <= max_message_bytes
/// 6. ML-DSA-65 signature valid over signing_input
pub fn verify_envelope(
    env: &GossipEnvelope,
    config: &ResolvedConfig,
    now_ms: u64,
) -> Result<bool, GossipError> {
    // Version check
    if env.version != 1 {
        return Err(GossipError::EnvelopeError(format!(
            "unsupported version: {}",
            env.version
        )));
    }

    // Message ID integrity
    let expected_id = compute_message_id(env.payload_type, &env.payload);
    if env.message_id != expected_id {
        return Err(GossipError::EnvelopeError(
            "message_id mismatch".to_string(),
        ));
    }

    // Replay protection
    let age_ms = now_ms.saturating_sub(env.timestamp_unix_ms);
    if age_ms > config.replay_window_ms {
        return Err(GossipError::ReplayDetected);
    }

    // TTL check
    if env.ttl == 0 {
        return Err(GossipError::TtlExpired);
    }

    // Size check
    if env.payload.len() > config.max_message_bytes {
        return Err(GossipError::EnvelopeError("payload too large".to_string()));
    }

    // Signature verification
    let input = signing_input(env);
    let verified = NodeIdentity::verify_external(
        &env.sender_public_key,
        &input,
        &env.signature,
        SIG_CTX_MESSAGE,
    )?;

    if !verified {
        return Err(GossipError::SignatureInvalid);
    }

    Ok(true)
}
