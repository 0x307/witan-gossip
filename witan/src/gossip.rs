//! GossipEngine — the central state machine.
//!
//! Owns all subsystems: identity, sessions, handshake manager, dedup cache,
//! quorum tracker, and stats. Stored as a global singleton in `lib.rs`.

use std::sync::Arc;

use crate::config::ResolvedConfig;
use crate::dedup::DedupCache;
use crate::envelope::{
    build_envelope, compute_message_id, decode_envelope, encode_envelope, verify_envelope,
};
use crate::error::GossipError;
use crate::handshake::HandshakeManager;
use crate::identity::NodeIdentity;
use crate::quorum::QuorumTracker;
use crate::session::{SessionRecord, SessionStore};
use crate::types::{GossipStats, PayloadType};

/// The central gossip engine.
///
/// Owns all subsystems. Stored behind `Mutex<Option<GossipEngine>>` in `lib.rs`.
pub struct GossipEngine {
    pub config: ResolvedConfig,
    pub identity: Arc<NodeIdentity>,
    pub sessions: SessionStore,
    pub handshakes: HandshakeManager,
    pub dedup: DedupCache,
    pub quorum: QuorumTracker,
    pub stats: GossipStats,
    /// Current mesh peers (subset of sessions, ≤ mesh_n_high).
    pub mesh_peers: Vec<String>,
}

impl GossipEngine {
    /// Create a new GossipEngine from resolved config and identity.
    pub fn new(config: ResolvedConfig, identity: NodeIdentity) -> Self {
        let dedup = DedupCache::new(config.dedup_cache_secs);
        let quorum = QuorumTracker::new(config.quorum_fraction);
        let mesh_capacity = config.mesh_n_high as usize;

        Self {
            identity: Arc::new(identity),
            sessions: SessionStore::new(),
            handshakes: HandshakeManager::new(),
            dedup,
            quorum,
            stats: GossipStats::default(),
            mesh_peers: Vec::with_capacity(mesh_capacity),
            config,
        }
    }

    // ── Peer Management ───────────────────────────────────────────────────────

    /// Initiate connection + handshake to a peer.
    ///
    /// Returns serialized HandshakeProbe bytes for the host to send.
    pub fn connect_peer(&mut self, peer_addr: &str, now_ms: u64) -> Result<Vec<u8>, GossipError> {
        // Check not already connected
        if self.sessions.get(peer_addr).is_some() {
            return Err(GossipError::HandshakeError(format!(
                "already connected to {peer_addr}"
            )));
        }

        // Build probe and store pending handshake
        let probe_bytes = self
            .handshakes
            .build_probe(peer_addr, &self.identity, now_ms)?;

        Ok(probe_bytes)
    }

    /// Process incoming handshake bytes from a peer.
    ///
    /// Returns optional response bytes for the host to send back.
    pub fn process_handshake_bytes(
        &mut self,
        peer_addr: &str,
        bytes: &[u8],
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, GossipError> {
        use crate::types::{classify_incoming, MessageKind};

        let kind = classify_incoming(bytes);

        match kind {
            // Server role: received probe from a connecting peer
            MessageKind::HandshakeProbe => {
                let ack_bytes = self.handshakes.process_probe_build_ack(
                    peer_addr,
                    bytes,
                    &self.identity,
                    now_ms,
                )?;
                Ok(Some(ack_bytes))
            }

            // Client role: received ACK from server
            MessageKind::HandshakeAck => {
                let finish_bytes = self.handshakes.process_ack_build_finish(
                    peer_addr,
                    bytes,
                    &self.identity,
                    now_ms,
                )?;
                Ok(Some(finish_bytes))
            }

            // Server role: received finish from client
            MessageKind::HandshakeFinish => {
                let (finish_ack_bytes, session) = self.handshakes.process_finish_build_finish_ack(
                    peer_addr,
                    bytes,
                    &self.identity,
                    now_ms,
                )?;
                self.complete_handshake(peer_addr, session);
                Ok(Some(finish_ack_bytes))
            }

            // Client role: received finish ACK from server
            MessageKind::HandshakeFinishAck => {
                let session =
                    self.handshakes
                        .process_finish_ack(peer_addr, bytes, now_ms)?;
                self.complete_handshake(peer_addr, session);
                Ok(None) // No response needed; handshake complete
            }

            MessageKind::GossipEnvelope => Err(GossipError::HandshakeError(
                "expected handshake message, got gossip envelope".to_string(),
            )),
        }
    }

    /// Check if a handshake is complete for a peer.
    pub fn is_handshake_complete(&self, peer_addr: &str) -> bool {
        self.sessions.get(peer_addr).is_some()
    }

    /// Complete a handshake: store session, add to mesh, update stats.
    fn complete_handshake(&mut self, peer_addr: &str, session: SessionRecord) {
        self.sessions.insert(session);
        self.add_to_mesh(peer_addr);
        self.stats.handshakes_completed += 1;
        self.stats.active_peers = self.sessions.count() as u32;
        self.stats.mesh_peers = self.mesh_peers.len() as u32;
    }

    /// Disconnect a peer, remove session.
    pub fn disconnect_peer(&mut self, peer_addr: &str) -> Result<(), GossipError> {
        self.sessions
            .remove(peer_addr)
            .ok_or_else(|| GossipError::PeerNotFound(peer_addr.to_string()))?;
        self.remove_from_mesh(peer_addr);
        self.handshakes.remove(peer_addr);
        self.stats.active_peers = self.sessions.count() as u32;
        self.stats.mesh_peers = self.mesh_peers.len() as u32;
        Ok(())
    }

    // ── Mesh Management ───────────────────────────────────────────────────────

    fn add_to_mesh(&mut self, peer_addr: &str) {
        if !self.mesh_peers.contains(&peer_addr.to_string())
            && self.mesh_peers.len() < self.config.mesh_n_high as usize
        {
            self.mesh_peers.push(peer_addr.to_string());
        }
    }

    fn remove_from_mesh(&mut self, peer_addr: &str) {
        self.mesh_peers.retain(|p| p != peer_addr);
    }

    fn mesh_is_full(&self) -> bool {
        self.mesh_peers.len() >= self.config.mesh_n_high as usize
    }

    fn mesh_needs_peers(&self) -> bool {
        self.mesh_peers.len() < self.config.mesh_n_low as usize
    }

    // ── Message Publishing ────────────────────────────────────────────────────

    /// Publish a message: build envelope, dedup-check, return message_id.
    ///
    /// Returns the 32-byte message ID. The host uses `encode_envelope` to get
    /// wire bytes for each peer.
    pub fn publish(
        &mut self,
        payload_type: u8,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<[u8; 32], GossipError> {
        // Validate payload type
        let pt = PayloadType::from_u8(payload_type).ok_or_else(|| {
            GossipError::InvalidInput(format!("unknown payload_type_id: {payload_type}"))
        })?;

        // Validate payload size
        if payload.len() > self.config.max_message_bytes {
            return Err(GossipError::InvalidInput(format!(
                "payload too large: {} > {}",
                payload.len(),
                self.config.max_message_bytes
            )));
        }

        // Compute message ID
        let message_id = compute_message_id(pt, payload);

        // Dedup check
        if self.dedup.is_duplicate(&message_id, now_ms) {
            self.stats.messages_deduplicated += 1;
            return Err(GossipError::EnvelopeError("duplicate message".to_string()));
        }
        self.dedup.insert(message_id, now_ms);

        // Build and sign envelope (we don't store it — host calls encode_envelope)
        let _envelope = build_envelope(pt, payload, &self.identity, self.config.default_ttl, now_ms)?;

        self.stats.messages_published += 1;
        Ok(message_id)
    }

    /// Encode a new signed GossipEnvelope to bincode bytes.
    pub fn encode_envelope(
        &mut self,
        payload_type: u8,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<Vec<u8>, GossipError> {
        let pt = PayloadType::from_u8(payload_type).ok_or_else(|| {
            GossipError::InvalidInput(format!("unknown payload_type_id: {payload_type}"))
        })?;

        let envelope = build_envelope(pt, payload, &self.identity, self.config.default_ttl, now_ms)?;
        encode_envelope(&envelope)
    }

    // ── Message Verification ──────────────────────────────────────────────────

    /// Verify a received envelope (bincode bytes).
    pub fn verify_envelope_bytes(
        &mut self,
        bytes: &[u8],
        now_ms: u64,
    ) -> Result<bool, GossipError> {
        let envelope = decode_envelope(bytes)?;

        match verify_envelope(&envelope, &self.config, now_ms) {
            Ok(true) => {
                self.stats.messages_received += 1;
                Ok(true)
            }
            Ok(false) => {
                self.stats.messages_dropped += 1;
                Ok(false)
            }
            Err(GossipError::ReplayDetected) => {
                self.stats.messages_dropped += 1;
                Err(GossipError::ReplayDetected)
            }
            Err(GossipError::TtlExpired) => {
                self.stats.messages_dropped += 1;
                Err(GossipError::TtlExpired)
            }
            Err(GossipError::SignatureInvalid) => {
                self.stats.messages_dropped += 1;
                Err(GossipError::SignatureInvalid)
            }
            Err(e) => {
                self.stats.messages_dropped += 1;
                Err(e)
            }
        }
    }

    /// Decode envelope bytes to JSON string.
    pub fn decode_envelope_to_json(&self, bytes: &[u8]) -> Result<String, GossipError> {
        let envelope = decode_envelope(bytes)?;
        serde_json::to_string(&envelope)
            .map_err(|e| GossipError::SerializationError(format!("JSON serialize: {e}")))
    }

    // ── API Responses ─────────────────────────────────────────────────────────

    /// Get JSON stats.
    pub fn get_stats_json(&self, now_ms: u64) -> Result<String, GossipError> {
        let _ = now_ms; // reserved for uptime calculation
        serde_json::to_string(&self.stats)
            .map_err(|e| GossipError::SerializationError(format!("JSON serialize: {e}")))
    }

    /// Get JSON peer list.
    pub fn get_peers_json(&self) -> Result<String, GossipError> {
        let peers = self.sessions.active_peers();
        serde_json::to_string(&peers)
            .map_err(|e| GossipError::SerializationError(format!("JSON serialize: {e}")))
    }

    /// Get JSON node identity (public parts).
    pub fn get_node_identity_json(&self) -> Result<String, GossipError> {
        let public_view = self.identity.public_view()?;
        serde_json::to_string(&public_view)
            .map_err(|e| GossipError::SerializationError(format!("JSON serialize: {e}")))
    }

    /// Get session info for a peer as JSON.
    pub fn get_session_json(&self, peer_addr: &str) -> Result<String, GossipError> {
        let session = self
            .sessions
            .get(peer_addr)
            .ok_or_else(|| GossipError::SessionNotFound(peer_addr.to_string()))?;

        let info = serde_json::json!({
            "session_id": session.session_id,
            "peer_addr": session.peer_addr,
            "peer_node_id": session.peer_node_id,
            "established_at_ms": session.established_at_ms,
            "is_active": session.is_active,
        });

        serde_json::to_string(&info)
            .map_err(|e| GossipError::SerializationError(format!("JSON serialize: {e}")))
    }

    // ── Heartbeat / Maintenance ───────────────────────────────────────────────

    /// Run periodic maintenance tasks.
    ///
    /// Called by the host periodically (or triggered by any API call).
    pub fn heartbeat(&mut self, now_ms: u64) {
        // 1. Evict dedup cache
        self.dedup.evict_expired(now_ms);

        // 2. Clean up timed-out handshakes
        let evicted = self.handshakes.evict_timed_out(now_ms);
        self.stats.handshakes_failed += evicted.len() as u32;

        // 3. Prune quorum tracker
        let active_ids = self.dedup.active_ids();
        self.quorum.prune(&active_ids);

        // 4. Mesh maintenance: graft if below low watermark
        if self.mesh_needs_peers() {
            let candidates: Vec<String> = self
                .sessions
                .active_peers()
                .into_iter()
                .map(|p| p.addr)
                .filter(|a| !self.mesh_peers.contains(a))
                .take(
                    (self.config.mesh_n as usize).saturating_sub(self.mesh_peers.len()),
                )
                .collect();

            for addr in candidates {
                if !self.mesh_is_full() {
                    self.mesh_peers.push(addr);
                }
            }
        }

        // 5. Update stats
        self.stats.active_peers = self.sessions.count() as u32;
        self.stats.mesh_peers = self.mesh_peers.len() as u32;
        self.stats.dedup_cache_size = self.dedup.len() as u32;
    }

    // ── Key Rotation ──────────────────────────────────────────────────────────

    /// Rotate node identity keys. Returns new node_id.
    ///
    /// Generates a fresh ephemeral identity. All existing sessions remain valid
    /// (they use the old keys for verification). New envelopes use the new keys.
    pub fn rotate_keys(&mut self, key_epoch: &str) -> Result<String, GossipError> {
        let new_identity = NodeIdentity::generate(key_epoch)?;
        let new_node_id = new_identity.node_id.clone();
        self.identity = Arc::new(new_identity);
        Ok(new_node_id)
    }

    // ── Standalone Signature Verification ────────────────────────────────────

    /// Verify a standalone ML-DSA-65 signature.
    pub fn verify_signature(
        public_key_bytes: &[u8],
        message: &[u8],
        signature: &[u8],
        context: &[u8],
    ) -> Result<bool, GossipError> {
        NodeIdentity::verify_external(public_key_bytes, message, signature, context)
    }
}
