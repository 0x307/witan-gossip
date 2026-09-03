//! PQC 4-message handshake state machine.
//!
//! Implements the X25519 + ML-KEM-768 + ML-DSA-65 handshake protocol.
//!
//! ## Protocol Flow
//! ```text
//! Client                                          Server
//!   |--- [1] HandshakeProbe ----------------------->|
//!   |<-- [2] HandshakeAck --------------------------|
//!   |--- [3] HandshakeFinish ---------------------->|
//!   |<-- [4] HandshakeFinishAck --------------------|
//!   |=== SESSION ESTABLISHED =======================|
//! ```

use std::collections::HashMap;

use pqc_kem::fips203::HybridKemKeypair;
use pqc_kem::types::HybridKemCiphertext;
use rand::rngs::OsRng;

use crate::error::GossipError;
use crate::identity::NodeIdentity;
use crate::session::{
    compute_server_mac, compute_transcript_hash, derive_session_id, SessionRecord,
};
use crate::types::{
    classify_incoming, HandshakeAck, HandshakeFinish, HandshakeFinishAck, HandshakeProbe,
    MessageKind, HANDSHAKE_ACK_MAGIC, HANDSHAKE_FINISH_ACK_MAGIC, HANDSHAKE_FINISH_MAGIC,
    HANDSHAKE_PROBE_MAGIC, SIG_CTX_HANDSHAKE,
};

/// Handshake timeout: 10 seconds.
const HANDSHAKE_TIMEOUT_MS: u64 = 10_000;

// ── Client-side state ─────────────────────────────────────────────────────────

/// Client-side handshake state machine.
pub enum ClientHandshakeState {
    /// Initial state — no handshake in progress.
    Idle,
    /// Probe sent; waiting for ACK from server.
    ProbeSent {
        client_nonce: [u8; 32],
        probe_bytes: Vec<u8>,
        sent_at_ms: u64,
    },
    /// Finish sent; waiting for FinishAck from server.
    FinishSent {
        client_nonce: [u8; 32],
        server_nonce: [u8; 32],
        kem_ciphertext_bytes: Vec<u8>,
        shared_secret_32b: [u8; 32],
        probe_bytes: Vec<u8>,
        ack_bytes: Vec<u8>,
        finish_bytes: Vec<u8>,
        server_sig_pk: Vec<u8>,
        server_node_id: String,
        sent_at_ms: u64,
    },
    /// Handshake complete.
    Complete(SessionRecord),
    /// Handshake failed.
    Failed(String),
}

// ── Server-side state ─────────────────────────────────────────────────────────

/// Server-side handshake state machine.
pub enum ServerHandshakeState {
    /// Initial state — no handshake in progress.
    Idle,
    /// ACK sent; waiting for Finish from client.
    /// Note: shared_secret and kem_ciphertext are derived when Finish arrives.
    AckSent {
        client_nonce: [u8; 32],
        server_nonce: [u8; 32],
        probe_bytes: Vec<u8>,
        ack_bytes: Vec<u8>,
        sent_at_ms: u64,
    },
    /// Handshake complete.
    Complete(SessionRecord),
    /// Handshake failed.
    Failed(String),
}

// ── HandshakeContext ──────────────────────────────────────────────────────────

/// Per-peer handshake context. Holds either client or server state.
pub enum HandshakeContext {
    Client(ClientHandshakeState),
    Server(ServerHandshakeState),
}

impl HandshakeContext {
    /// Create a new client-side context (Idle state).
    pub fn new_client() -> Self {
        HandshakeContext::Client(ClientHandshakeState::Idle)
    }

    /// Create a new server-side context with the given state.
    pub fn new_server(state: ServerHandshakeState) -> Self {
        HandshakeContext::Server(state)
    }

    /// Check if this handshake has timed out.
    pub fn is_timed_out(&self, now_ms: u64) -> bool {
        match self {
            HandshakeContext::Client(ClientHandshakeState::ProbeSent { sent_at_ms, .. }) => {
                now_ms.saturating_sub(*sent_at_ms) > HANDSHAKE_TIMEOUT_MS
            }
            HandshakeContext::Client(ClientHandshakeState::FinishSent { sent_at_ms, .. }) => {
                now_ms.saturating_sub(*sent_at_ms) > HANDSHAKE_TIMEOUT_MS
            }
            HandshakeContext::Server(ServerHandshakeState::AckSent { sent_at_ms, .. }) => {
                now_ms.saturating_sub(*sent_at_ms) > HANDSHAKE_TIMEOUT_MS
            }
            _ => false,
        }
    }

    /// Check if the handshake is complete.
    pub fn is_complete(&self) -> bool {
        matches!(
            self,
            HandshakeContext::Client(ClientHandshakeState::Complete(_))
                | HandshakeContext::Server(ServerHandshakeState::Complete(_))
        )
    }

    /// Extract the completed session record (consumes the context).
    pub fn into_session(self) -> Option<SessionRecord> {
        match self {
            HandshakeContext::Client(ClientHandshakeState::Complete(s)) => Some(s),
            HandshakeContext::Server(ServerHandshakeState::Complete(s)) => Some(s),
            _ => None,
        }
    }
}

// ── HandshakeManager ──────────────────────────────────────────────────────────

/// Manages all pending handshakes for the gossip engine.
pub struct HandshakeManager {
    /// peer_addr -> HandshakeContext (in-progress handshakes)
    pending: HashMap<String, HandshakeContext>,
    /// peer_addr -> SessionRecord (completed handshakes)
    completed: HashMap<String, crate::session::SessionRecord>,
}

impl HandshakeManager {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            completed: HashMap::new(),
        }
    }

    /// CLIENT STEP 1: Build identity probe bytes to send to server.
    ///
    /// Returns: bincode-encoded HandshakeProbe bytes.
    pub fn build_probe(
        &mut self,
        peer_addr: &str,
        identity: &NodeIdentity,
        now_ms: u64,
    ) -> Result<Vec<u8>, GossipError> {
        // Generate 32-byte random client nonce
        let mut client_nonce = [0u8; 32];
        getrandom::getrandom(&mut client_nonce)
            .map_err(|e| GossipError::CryptoError(format!("getrandom failed: {e}")))?;

        let probe = HandshakeProbe {
            magic: HANDSHAKE_PROBE_MAGIC.to_vec(),
            version: 1,
            client_nonce,
            endpoint: peer_addr.to_string(),
            client_node_id: identity.node_id.clone(),
            timestamp_unix_ms: now_ms,
        };

        let probe_bytes = bincode::serialize(&probe)
            .map_err(|e| GossipError::SerializationError(format!("probe serialize: {e}")))?;

        // Store client state
        self.pending.insert(
            peer_addr.to_string(),
            HandshakeContext::Client(ClientHandshakeState::ProbeSent {
                client_nonce,
                probe_bytes: probe_bytes.clone(),
                sent_at_ms: now_ms,
            }),
        );

        Ok(probe_bytes)
    }

    /// SERVER STEP 1: Process identity probe, return identity ACK bytes.
    ///
    /// Input: HandshakeProbe bincode bytes.
    /// Returns: bincode-encoded HandshakeAck bytes.
    pub fn process_probe_build_ack(
        &mut self,
        peer_addr: &str,
        probe_bytes: &[u8],
        identity: &NodeIdentity,
        now_ms: u64,
    ) -> Result<Vec<u8>, GossipError> {
        // Deserialize probe
        let probe: HandshakeProbe = bincode::deserialize(probe_bytes)
            .map_err(|e| GossipError::HandshakeError(format!("probe deserialize: {e}")))?;

        // Validate magic
        if probe.magic != HANDSHAKE_PROBE_MAGIC {
            return Err(GossipError::HandshakeError("invalid probe magic".to_string()));
        }
        if probe.version != 1 {
            return Err(GossipError::HandshakeError(format!(
                "version mismatch: expected 1, got {}",
                probe.version
            )));
        }

        // Timestamp check
        let age_ms = now_ms.saturating_sub(probe.timestamp_unix_ms);
        if age_ms > 30_000 {
            return Err(GossipError::HandshakeError(
                "timestamp out of window".to_string(),
            ));
        }

        // Generate server nonce
        let mut server_nonce = [0u8; 32];
        getrandom::getrandom(&mut server_nonce)
            .map_err(|e| GossipError::CryptoError(format!("getrandom failed: {e}")))?;

        // Get KEM public key as JSON
        let kem_pk = identity.kem_keypair.public_key();
        let kem_pk_json = kem_pk
            .to_json()
            .map_err(|e| GossipError::CryptoError(format!("KEM pk to_json: {e}")))?;

        // Get SIG public key bytes
        let sig_pk_bytes = identity.sig_public_key_bytes();

        let ack = HandshakeAck {
            magic: HANDSHAKE_ACK_MAGIC.to_vec(),
            version: 1,
            client_nonce: probe.client_nonce,
            server_nonce,
            hybrid_kem_public_key_json: kem_pk_json,
            ml_dsa_65_public_key: sig_pk_bytes,
            server_node_id: identity.node_id.clone(),
            timestamp_unix_ms: now_ms,
        };

        let ack_bytes = bincode::serialize(&ack)
            .map_err(|e| GossipError::SerializationError(format!("ack serialize: {e}")))?;

        // Store server state
        self.pending.insert(
            peer_addr.to_string(),
            HandshakeContext::Server(ServerHandshakeState::AckSent {
                client_nonce: probe.client_nonce,
                server_nonce,
                probe_bytes: probe_bytes.to_vec(),
                ack_bytes: ack_bytes.clone(),
                sent_at_ms: now_ms,
            }),
        );

        Ok(ack_bytes)
    }

    /// CLIENT STEP 2: Process identity ACK, return finish probe bytes.
    ///
    /// Input: HandshakeAck bincode bytes.
    /// Returns: bincode-encoded HandshakeFinish bytes.
    pub fn process_ack_build_finish(
        &mut self,
        peer_addr: &str,
        ack_bytes: &[u8],
        identity: &NodeIdentity,
        now_ms: u64,
    ) -> Result<Vec<u8>, GossipError> {
        // Deserialize ACK
        let ack: HandshakeAck = bincode::deserialize(ack_bytes)
            .map_err(|e| GossipError::HandshakeError(format!("ack deserialize: {e}")))?;

        // Validate magic
        if ack.magic != HANDSHAKE_ACK_MAGIC {
            return Err(GossipError::HandshakeError("invalid ack magic".to_string()));
        }
        if ack.version != 1 {
            return Err(GossipError::HandshakeError(format!(
                "version mismatch: expected 1, got {}",
                ack.version
            )));
        }

        // Timestamp check
        let age_ms = now_ms.saturating_sub(ack.timestamp_unix_ms);
        if age_ms > 30_000 {
            return Err(GossipError::HandshakeError(
                "timestamp out of window".to_string(),
            ));
        }

        // Validate SIG public key size
        if ack.ml_dsa_65_public_key.len() != 1952 {
            return Err(GossipError::HandshakeError(format!(
                "invalid sig pk size: expected 1952, got {}",
                ack.ml_dsa_65_public_key.len()
            )));
        }

        // Get client state to verify nonce echo
        let (client_nonce, probe_bytes) = match self.pending.get(peer_addr) {
            Some(HandshakeContext::Client(ClientHandshakeState::ProbeSent {
                client_nonce,
                probe_bytes,
                ..
            })) => (*client_nonce, probe_bytes.clone()),
            _ => {
                return Err(GossipError::HandshakeError(format!(
                    "no pending client handshake for {peer_addr}"
                )))
            }
        };

        // Verify nonce echo
        if ack.client_nonce != client_nonce {
            return Err(GossipError::HandshakeError("nonce mismatch".to_string()));
        }

        // Parse server's KEM public key
        let server_kem_pk = pqc_kem::types::HybridPublicKey::from_json(&ack.hybrid_kem_public_key_json)
            .map_err(|e| GossipError::CryptoError(format!("KEM pk from_json: {e}")))?;

        // Encapsulate: generates (ciphertext, shared_secret)
        let mut rng = OsRng;
        let (ciphertext, shared_secret) = HybridKemKeypair::encapsulate_to(&mut rng, &server_kem_pk)
            .map_err(|e| GossipError::CryptoError(format!("KEM encapsulate failed: {e}")))?;

        // Get shared secret as 32 bytes
        let shared_secret_32b = shared_secret
            .as_32_bytes()
            .map_err(|e| GossipError::CryptoError(format!("shared secret not 32 bytes: {e}")))?;

        // Serialize ciphertext to JSON (for wire)
        let ciphertext_json = ciphertext
            .to_json()
            .map_err(|e| GossipError::CryptoError(format!("ciphertext to_json: {e}")))?;

        // Serialize ciphertext to bytes (for session ID derivation)
        let kem_ciphertext_bytes = bincode::serialize(&ciphertext)
            .map_err(|e| GossipError::SerializationError(format!("ciphertext serialize: {e}")))?;

        // Get client SIG public key bytes
        let sig_pk_bytes = identity.sig_public_key_bytes();

        let finish = HandshakeFinish {
            magic: HANDSHAKE_FINISH_MAGIC.to_vec(),
            version: 1,
            kem_ciphertext_json: ciphertext_json,
            client_ml_dsa_65_public_key: sig_pk_bytes,
            client_node_id: identity.node_id.clone(),
            timestamp_unix_ms: now_ms,
        };

        let finish_bytes = bincode::serialize(&finish)
            .map_err(|e| GossipError::SerializationError(format!("finish serialize: {e}")))?;

        // Update client state to FinishSent
        self.pending.insert(
            peer_addr.to_string(),
            HandshakeContext::Client(ClientHandshakeState::FinishSent {
                client_nonce,
                server_nonce: ack.server_nonce,
                kem_ciphertext_bytes,
                shared_secret_32b,
                probe_bytes,
                ack_bytes: ack_bytes.to_vec(),
                finish_bytes: finish_bytes.clone(),
                server_sig_pk: ack.ml_dsa_65_public_key,
                server_node_id: ack.server_node_id,
                sent_at_ms: now_ms,
            }),
        );

        Ok(finish_bytes)
    }

    /// SERVER STEP 2: Process finish probe, return finish ACK bytes.
    ///
    /// Input: HandshakeFinish bincode bytes.
    /// Returns: bincode-encoded HandshakeFinishAck bytes.
    pub fn process_finish_build_finish_ack(
        &mut self,
        peer_addr: &str,
        finish_bytes: &[u8],
        identity: &NodeIdentity,
        now_ms: u64,
    ) -> Result<(Vec<u8>, SessionRecord), GossipError> {
        // Deserialize finish
        let finish: HandshakeFinish = bincode::deserialize(finish_bytes)
            .map_err(|e| GossipError::HandshakeError(format!("finish deserialize: {e}")))?;

        // Validate magic
        if finish.magic != HANDSHAKE_FINISH_MAGIC {
            return Err(GossipError::HandshakeError(
                "invalid finish magic".to_string(),
            ));
        }
        if finish.version != 1 {
            return Err(GossipError::HandshakeError(format!(
                "version mismatch: expected 1, got {}",
                finish.version
            )));
        }

        // Timestamp check
        let age_ms = now_ms.saturating_sub(finish.timestamp_unix_ms);
        if age_ms > 30_000 {
            return Err(GossipError::HandshakeError(
                "timestamp out of window".to_string(),
            ));
        }

        // Validate client SIG public key size
        if finish.client_ml_dsa_65_public_key.len() != 1952 {
            return Err(GossipError::HandshakeError(format!(
                "invalid client sig pk size: expected 1952, got {}",
                finish.client_ml_dsa_65_public_key.len()
            )));
        }

        // Get server state
        let (client_nonce, server_nonce, probe_bytes, ack_bytes) =
            match self.pending.remove(peer_addr) {
                Some(HandshakeContext::Server(ServerHandshakeState::AckSent {
                    client_nonce,
                    server_nonce,
                    probe_bytes,
                    ack_bytes,
                    ..
                })) => (client_nonce, server_nonce, probe_bytes, ack_bytes),
                _ => {
                    return Err(GossipError::HandshakeError(format!(
                        "no pending server handshake for {peer_addr}"
                    )))
                }
            };

        // Parse KEM ciphertext from JSON
        let ciphertext = HybridKemCiphertext::from_json(&finish.kem_ciphertext_json)
            .map_err(|e| GossipError::CryptoError(format!("ciphertext from_json: {e}")))?;

        // Decapsulate: recover shared secret
        let shared_secret = identity
            .kem_keypair
            .decapsulate(&ciphertext)
            .map_err(|e| GossipError::CryptoError(format!("KEM decapsulate failed: {e}")))?;

        let shared_secret_32b = shared_secret
            .as_32_bytes()
            .map_err(|e| GossipError::CryptoError(format!("shared secret not 32 bytes: {e}")))?;

        // Serialize ciphertext to bytes for session ID derivation
        let kem_ciphertext_bytes = bincode::serialize(&ciphertext)
            .map_err(|e| GossipError::SerializationError(format!("ciphertext serialize: {e}")))?;

        // Compute transcript hash: SHA-256(probe || ack || finish)
        let transcript_hash = compute_transcript_hash(&probe_bytes, &ack_bytes, finish_bytes);

        // Compute server MAC: HMAC-SHA256(shared_secret, transcript_hash)
        let server_mac = compute_server_mac(&shared_secret_32b, &transcript_hash);

        // Sign transcript hash with ML-DSA-65
        let transcript_signature = identity.sign(&transcript_hash, SIG_CTX_HANDSHAKE)?;

        // Derive session ID
        let session_id = derive_session_id(
            &shared_secret_32b,
            &client_nonce,
            &server_nonce,
            &kem_ciphertext_bytes,
            &identity.node_id,
        );

        let finish_ack = HandshakeFinishAck {
            magic: HANDSHAKE_FINISH_ACK_MAGIC.to_vec(),
            version: 1,
            session_id: session_id.clone(),
            transcript_hash,
            server_mac,
            transcript_signature,
            timestamp_unix_ms: now_ms,
        };

        let finish_ack_bytes = bincode::serialize(&finish_ack)
            .map_err(|e| GossipError::SerializationError(format!("finish_ack serialize: {e}")))?;

        let session = SessionRecord {
            session_id,
            peer_addr: peer_addr.to_string(),
            peer_node_id: finish.client_node_id,
            peer_sig_public_key: finish.client_ml_dsa_65_public_key,
            transcript_hash,
            established_at_ms: now_ms,
            is_active: true,
        };

        Ok((finish_ack_bytes, session))
    }

    /// CLIENT STEP 3: Process finish ACK, complete handshake.
    ///
    /// Input: HandshakeFinishAck bincode bytes.
    /// Returns: completed SessionRecord.
    pub fn process_finish_ack(
        &mut self,
        peer_addr: &str,
        finish_ack_bytes: &[u8],
        now_ms: u64,
    ) -> Result<SessionRecord, GossipError> {
        // Deserialize finish ACK
        let finish_ack: HandshakeFinishAck = bincode::deserialize(finish_ack_bytes)
            .map_err(|e| GossipError::HandshakeError(format!("finish_ack deserialize: {e}")))?;

        // Validate magic
        if finish_ack.magic != HANDSHAKE_FINISH_ACK_MAGIC {
            return Err(GossipError::HandshakeError(
                "invalid finish_ack magic".to_string(),
            ));
        }
        if finish_ack.version != 1 {
            return Err(GossipError::HandshakeError(format!(
                "version mismatch: expected 1, got {}",
                finish_ack.version
            )));
        }

        // Timestamp check
        let age_ms = now_ms.saturating_sub(finish_ack.timestamp_unix_ms);
        if age_ms > 30_000 {
            return Err(GossipError::HandshakeError(
                "timestamp out of window".to_string(),
            ));
        }

        // Get client state
        let (
            shared_secret_32b,
            probe_bytes,
            ack_bytes,
            finish_bytes,
            server_sig_pk,
            server_node_id,
        ) = match self.pending.remove(peer_addr) {
            Some(HandshakeContext::Client(ClientHandshakeState::FinishSent {
                shared_secret_32b,
                probe_bytes,
                ack_bytes,
                finish_bytes,
                server_sig_pk,
                server_node_id,
                ..
            })) => (
                shared_secret_32b,
                probe_bytes,
                ack_bytes,
                finish_bytes,
                server_sig_pk,
                server_node_id,
            ),
            _ => {
                return Err(GossipError::HandshakeError(format!(
                    "no pending client finish for {peer_addr}"
                )))
            }
        };

        // Recompute transcript hash
        let expected_transcript_hash =
            compute_transcript_hash(&probe_bytes, &ack_bytes, &finish_bytes);

        // Verify transcript hash matches
        if finish_ack.transcript_hash != expected_transcript_hash {
            return Err(GossipError::HandshakeError(
                "transcript hash mismatch".to_string(),
            ));
        }

        // Recompute server MAC and verify (constant-time comparison via hmac)
        let expected_mac = compute_server_mac(&shared_secret_32b, &expected_transcript_hash);
        if !constant_time_eq(&finish_ack.server_mac, &expected_mac) {
            return Err(GossipError::HandshakeError(
                "mac verification failed".to_string(),
            ));
        }

        // Verify ML-DSA-65 transcript signature
        let sig_valid = NodeIdentity::verify_external(
            &server_sig_pk,
            &finish_ack.transcript_hash,
            &finish_ack.transcript_signature,
            SIG_CTX_HANDSHAKE,
        )?;

        if !sig_valid {
            return Err(GossipError::HandshakeError(
                "transcript signature invalid".to_string(),
            ));
        }

        let session = SessionRecord {
            session_id: finish_ack.session_id,
            peer_addr: peer_addr.to_string(),
            peer_node_id: server_node_id,
            peer_sig_public_key: server_sig_pk,
            transcript_hash: finish_ack.transcript_hash,
            established_at_ms: now_ms,
            is_active: true,
        };

        Ok(session)
    }

    /// Route incoming bytes to the correct handler based on magic prefix.
    ///
    /// Returns response bytes (empty vec if no response needed / handshake complete).
    /// Completed sessions are stored internally and accessible via `get_session()`.
    pub fn process_incoming(
        &mut self,
        peer_addr: &str,
        bytes: &[u8],
        identity: &NodeIdentity,
        now_ms: u64,
    ) -> Result<Vec<u8>, GossipError> {
        let kind = classify_incoming(bytes);

        match kind {
            // Server role: received probe from a connecting peer
            MessageKind::HandshakeProbe => {
                let ack_bytes =
                    self.process_probe_build_ack(peer_addr, bytes, identity, now_ms)?;
                Ok(ack_bytes)
            }

            // Client role: received ACK from server
            MessageKind::HandshakeAck => {
                let finish_bytes =
                    self.process_ack_build_finish(peer_addr, bytes, identity, now_ms)?;
                Ok(finish_bytes)
            }

            // Server role: received finish from client
            MessageKind::HandshakeFinish => {
                let (finish_ack_bytes, session) =
                    self.process_finish_build_finish_ack(peer_addr, bytes, identity, now_ms)?;
                // Store the completed session
                self.completed.insert(peer_addr.to_string(), session);
                Ok(finish_ack_bytes)
            }

            // Client role: received finish ACK from server
            MessageKind::HandshakeFinishAck => {
                let session = self.process_finish_ack(peer_addr, bytes, now_ms)?;
                // Store the completed session
                self.completed.insert(peer_addr.to_string(), session);
                Ok(Vec::new()) // No response needed; handshake complete
            }

            MessageKind::GossipEnvelope => Err(GossipError::HandshakeError(
                "expected handshake message, got gossip envelope".to_string(),
            )),
        }
    }

    /// Check if a handshake is complete for a peer.
    pub fn is_complete(&self, peer_addr: &str) -> bool {
        self.completed.contains_key(peer_addr)
    }

    /// Check if a handshake is complete for a peer (alias for `is_complete`).
    pub fn is_handshake_complete(&self, peer_addr: &str) -> bool {
        self.is_complete(peer_addr)
    }

    /// Get the completed session for a peer (if handshake is done).
    pub fn get_session(&self, peer_addr: &str) -> Option<&crate::session::SessionRecord> {
        self.completed.get(peer_addr)
    }

    /// Create an identity probe for a peer (alias for `build_probe` using current time).
    pub fn create_identity_probe(
        &mut self,
        peer_addr: &str,
        identity: &NodeIdentity,
    ) -> Result<Vec<u8>, GossipError> {
        let now_ms = crate::api::current_time_unix_ms();
        self.build_probe(peer_addr, identity, now_ms)
    }

    /// Remove a pending handshake context.
    pub fn remove(&mut self, peer_addr: &str) {
        self.pending.remove(peer_addr);
        self.completed.remove(peer_addr);
    }

    /// Evict timed-out handshakes. Returns list of evicted peer addrs.
    pub fn evict_timed_out(&mut self, now_ms: u64) -> Vec<String> {
        let mut evicted = Vec::new();
        self.pending.retain(|addr, ctx| {
            if ctx.is_timed_out(now_ms) {
                evicted.push(addr.clone());
                false
            } else {
                true
            }
        });
        evicted
    }

    /// Get the completed session for a peer (if handshake just finished via process_incoming).
    ///
    /// Note: After process_finish_build_finish_ack or process_finish_ack, the session
    /// is returned directly. This method is for checking if a context holds a complete session.
    pub fn take_session(&mut self, peer_addr: &str) -> Option<SessionRecord> {
        if let Some(ctx) = self.pending.remove(peer_addr) {
            ctx.into_session()
        } else {
            None
        }
    }
}

impl Default for HandshakeManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Constant-time comparison of two byte slices.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
