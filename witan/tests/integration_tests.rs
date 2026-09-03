//! Integration tests for witan.
//!
//! Tests cover: identity generation, signing, envelope encode/decode,
//! replay detection, dedup cache, quorum tracker, handshake, API, and config.

use std::sync::Once;

use witan::{
    gossip_decode_envelope, gossip_encode_envelope, gossip_get_node_identity, gossip_get_stats,
    gossip_get_version, gossip_init, gossip_publish, gossip_verify_envelope,
    identity::NodeIdentity,
    types::PayloadType,
};

// ── Shared gossip_init guard ──────────────────────────────────────────────────
//
// gossip_init uses OnceLock — it can only succeed once per process.
// All tests that need the global engine share this initialization.

static INIT: Once = Once::new();

fn ensure_gossip_init() {
    INIT.call_once(|| {
        gossip_init("{}").expect("gossip_init failed");
    });
}

// ── Test 1: Node identity generation ─────────────────────────────────────────

#[test]
fn test_node_identity_generate() {
    let identity = NodeIdentity::generate("test").expect("generate failed");

    // node_id must be 64-char hex (SHA-256 = 32 bytes = 64 hex chars)
    assert_eq!(identity.node_id.len(), 64, "node_id must be 64 hex chars");
    assert!(
        identity.node_id.chars().all(|c| c.is_ascii_hexdigit()),
        "node_id must be lowercase hex"
    );

    // KEM public key JSON must be valid JSON
    let kem_json = identity
        .kem_public_key_json()
        .expect("kem_public_key_json failed");
    let _parsed: serde_json::Value =
        serde_json::from_str(&kem_json).expect("kem_public_key_json is not valid JSON");

    // SIG public key hex must be 1952 bytes = 3904 hex chars
    let sig_hex = identity.sig_public_key_hex();
    assert_eq!(
        sig_hex.len(),
        3904,
        "sig_public_key_hex must be 3904 chars (1952 bytes)"
    );
    assert!(
        sig_hex.chars().all(|c| c.is_ascii_hexdigit()),
        "sig_public_key_hex must be hex"
    );
}

// ── Test 2: Node identity from seeds (deterministic) ─────────────────────────

#[test]
fn test_node_identity_from_seeds() {
    // Fixed seeds: 32 bytes x25519, 64 bytes mlkem, 32 bytes sig
    let x25519_seed = [0x01u8; 32];
    let mlkem_seed = [0x02u8; 64];
    let sig_seed = [0x03u8; 32];

    let id1 = NodeIdentity::from_seeds(&x25519_seed, &mlkem_seed, &sig_seed, "test")
        .expect("from_seeds #1 failed");
    let id2 = NodeIdentity::from_seeds(&x25519_seed, &mlkem_seed, &sig_seed, "test")
        .expect("from_seeds #2 failed");

    // Deterministic: same seeds → same node_id
    assert_eq!(
        id1.node_id, id2.node_id,
        "node_id must be deterministic from seeds"
    );

    // node_id must be 64-char hex
    assert_eq!(id1.node_id.len(), 64);
}

// ── Test 3: Sign and verify ───────────────────────────────────────────────────

#[test]
fn test_sign_and_verify() {
    let identity = NodeIdentity::generate("test").expect("generate failed");
    let message = b"hello witan gossip";
    let context = b"WITAN_GOSSIP_MESSAGE_V1";

    // Sign
    let signature = identity.sign(message, context).expect("sign failed");
    assert!(!signature.is_empty(), "signature must not be empty");

    // Verify with correct message and context → true
    let valid = identity
        .verify(message, &signature, context)
        .expect("verify failed");
    assert!(valid, "signature must verify correctly");

    // Verify with wrong message → false
    let wrong_msg = b"wrong message";
    let invalid_msg = identity
        .verify(wrong_msg, &signature, context)
        .expect("verify (wrong msg) failed");
    assert!(!invalid_msg, "wrong message must not verify");

    // Verify with wrong context → false
    let wrong_ctx = b"WRONG_CONTEXT";
    let invalid_ctx = identity
        .verify(message, &signature, wrong_ctx)
        .expect("verify (wrong ctx) failed");
    assert!(!invalid_ctx, "wrong context must not verify");
}

// ── Test 4: Envelope encode/decode roundtrip ──────────────────────────────────

#[test]
fn test_envelope_roundtrip() {
    ensure_gossip_init();

    // Encode an envelope
    let payload = b"hello world";
    let bytes = gossip_encode_envelope(PayloadType::Transaction as u8, payload)
        .expect("gossip_encode_envelope failed");
    assert!(!bytes.is_empty(), "encoded bytes must not be empty");

    // Decode to JSON
    let json_str = gossip_decode_envelope(&bytes).expect("gossip_decode_envelope failed");
    let parsed: serde_json::Value =
        serde_json::from_str(&json_str).expect("decoded JSON is invalid");

    // Verify fields
    assert_eq!(parsed["version"], 1, "version must be 1");
    assert!(
        parsed["message_id"].is_array(),
        "message_id must be an array"
    );
    assert!(
        parsed["sender_node_id"].is_string(),
        "sender_node_id must be a string"
    );
    assert_eq!(
        parsed["sender_node_id"].as_str().unwrap().len(),
        64,
        "sender_node_id must be 64 hex chars"
    );
    assert_eq!(parsed["ttl"], 8, "default ttl must be 8");

    // Verify envelope signature
    let valid = gossip_verify_envelope(&bytes).expect("gossip_verify_envelope failed");
    assert!(valid, "envelope must verify correctly");
}

// ── Test 5: Envelope replay detection ────────────────────────────────────────

#[test]
fn test_envelope_replay_detection() {
    use witan::{
        config::GossipConfig,
        envelope::{build_envelope, encode_envelope},
        types::PayloadType,
    };

    // Build a fresh identity and config for this test (no global state needed)
    let identity = NodeIdentity::generate("test").expect("generate failed");
    let config = GossipConfig {
        node_id: None,
        kem_seed_hex: None,
        sig_seed_hex: None,
        key_epoch: None,
        mesh_n: None,
        mesh_n_low: None,
        mesh_n_high: None,
        heartbeat_ms: None,
        max_message_bytes: None,
        dedup_cache_secs: None,
        quorum_fraction: None,
        replay_window_ms: Some(30_000),
        default_ttl: None,
    }
    .resolve()
    .expect("resolve failed");

    // Create envelope with timestamp 60 seconds in the past
    let now_ms = witan::current_time_unix_ms();
    let old_timestamp_ms = now_ms.saturating_sub(60_000); // 60s ago — outside 30s window

    let envelope = build_envelope(
        PayloadType::Transaction,
        b"stale payload",
        &identity,
        8,
        old_timestamp_ms,
    )
    .expect("build_envelope failed");

    let bytes = encode_envelope(&envelope).expect("encode_envelope failed");

    // verify_envelope should return ReplayDetected error
    use witan::envelope::verify_envelope;
    let result = verify_envelope(&envelope, &config, now_ms);
    assert!(
        result.is_err(),
        "stale envelope must fail verification"
    );
    match result.unwrap_err() {
        witan::GossipError::ReplayDetected => {}
        e => panic!("expected ReplayDetected, got: {e:?}"),
    }

    // Also verify via the raw bytes path (using a fresh config with the same window)
    // We can't use gossip_verify_envelope here because it uses the global engine's config.
    // Instead, verify the error type is correct from the direct call above.
    let _ = bytes; // suppress unused warning
}

// ── Test 6: Dedup cache ───────────────────────────────────────────────────────

#[test]
fn test_dedup_cache() {
    use witan::dedup::DedupCache;

    // Create cache with 1-second TTL
    let mut cache = DedupCache::new(1);

    let message_id = [0x42u8; 32];
    let now_ms: u64 = 1_000_000; // arbitrary base time

    // Not yet inserted → not a duplicate
    assert!(
        !cache.is_duplicate(&message_id, now_ms),
        "fresh message must not be duplicate"
    );

    // Insert
    cache.insert(message_id, now_ms);

    // Immediately after insert → is a duplicate
    assert!(
        cache.is_duplicate(&message_id, now_ms),
        "just-inserted message must be duplicate"
    );

    // After TTL expires (now_ms + 1001ms > ttl of 1000ms)
    let after_ttl_ms = now_ms + 1_001;
    assert!(
        !cache.is_duplicate(&message_id, after_ttl_ms),
        "expired message must not be duplicate"
    );

    // Cache should be empty after eviction
    assert_eq!(cache.len(), 0, "cache must be empty after TTL eviction");
}

// ── Test 7: Quorum tracker ────────────────────────────────────────────────────

#[test]
fn test_quorum_tracker() {
    use witan::quorum::QuorumTracker;

    // 0.67 * 4 = 2.68 → ceil = 3 required
    let mut tracker = QuorumTracker::new(0.67);
    let message_id = [0xABu8; 32];
    let total_peers = 4;

    // 0 acks → no quorum
    assert!(
        !tracker.has_quorum(&message_id, total_peers),
        "0 acks must not reach quorum"
    );

    // 1 ack → no quorum
    tracker.record_ack(&message_id, "peer-1");
    assert!(
        !tracker.has_quorum(&message_id, total_peers),
        "1 ack must not reach quorum"
    );

    // 2 acks → no quorum (need 3)
    tracker.record_ack(&message_id, "peer-2");
    assert!(
        !tracker.has_quorum(&message_id, total_peers),
        "2 acks must not reach quorum"
    );

    // 3 acks → quorum reached
    tracker.record_ack(&message_id, "peer-3");
    assert!(
        tracker.has_quorum(&message_id, total_peers),
        "3 acks must reach quorum (ceil(0.67 * 4) = 3)"
    );

    // Duplicate ack from same peer doesn't double-count
    tracker.record_ack(&message_id, "peer-1");
    assert_eq!(tracker.ack_count(&message_id), 3, "duplicate ack must not increase count");
}

// ── Test 8: Full handshake simulation ────────────────────────────────────────

#[test]
fn test_handshake_full_roundtrip() {
    use witan::{handshake::HandshakeManager, identity::NodeIdentity};

    // Create two node identities
    let alice = NodeIdentity::generate("test").expect("alice generate failed");
    let bob = NodeIdentity::generate("test").expect("bob generate failed");

    let mut alice_hs = HandshakeManager::new();
    let mut bob_hs = HandshakeManager::new();

    let now_ms = witan::current_time_unix_ms();

    // Step 1: Alice creates identity probe
    let probe = alice_hs
        .build_probe("bob-addr", &alice, now_ms)
        .expect("build_probe failed");
    assert!(!probe.is_empty(), "probe must not be empty");

    // Step 2: Bob processes probe, returns identity ACK
    let ack = bob_hs
        .process_incoming("alice-addr", &probe, &bob, now_ms)
        .expect("bob process_incoming (probe) failed");
    assert!(!ack.is_empty(), "ack must not be empty");

    // Step 3: Alice processes ACK, returns finish probe
    let finish = alice_hs
        .process_incoming("bob-addr", &ack, &alice, now_ms)
        .expect("alice process_incoming (ack) failed");
    assert!(!finish.is_empty(), "finish must not be empty");

    // Step 4: Bob processes finish probe, returns finish ACK
    let finish_ack = bob_hs
        .process_incoming("alice-addr", &finish, &bob, now_ms)
        .expect("bob process_incoming (finish) failed");
    assert!(!finish_ack.is_empty(), "finish_ack must not be empty");

    // Step 5: Alice processes finish ACK, handshake complete
    let result = alice_hs
        .process_incoming("bob-addr", &finish_ack, &alice, now_ms)
        .expect("alice process_incoming (finish_ack) failed");
    // result is empty (no more messages needed)
    assert!(result.is_empty(), "no response needed after finish_ack");

    // Both sides should have completed sessions
    assert!(
        alice_hs.is_handshake_complete("bob-addr"),
        "alice must have completed handshake with bob"
    );
    assert!(
        bob_hs.is_handshake_complete("alice-addr"),
        "bob must have completed handshake with alice"
    );

    // Session IDs should match (same shared secret → same HKDF output)
    let alice_session = alice_hs
        .get_session("bob-addr")
        .expect("alice must have session for bob");
    let bob_session = bob_hs
        .get_session("alice-addr")
        .expect("bob must have session for alice");

    assert_eq!(
        alice_session.session_id, bob_session.session_id,
        "session IDs must match (same shared secret)"
    );
}

// ── Test 9: Full API integration ──────────────────────────────────────────────

#[test]
fn test_full_api_integration() {
    ensure_gossip_init();

    // Get node identity
    let identity_json = gossip_get_node_identity().expect("gossip_get_node_identity failed");
    let identity: serde_json::Value =
        serde_json::from_str(&identity_json).expect("identity JSON invalid");
    assert_eq!(
        identity["node_id"].as_str().unwrap().len(),
        64,
        "node_id must be 64 hex chars"
    );

    // Publish a message
    let message_id = gossip_publish(0, b"test transaction").expect("gossip_publish failed");
    assert_eq!(message_id.len(), 32, "message_id must be 32 bytes");

    // Get stats — messages_published must be >= 1
    let stats_json = gossip_get_stats().expect("gossip_get_stats failed");
    let stats: serde_json::Value =
        serde_json::from_str(&stats_json).expect("stats JSON invalid");
    assert!(
        stats["messages_published"].as_u64().unwrap() >= 1,
        "messages_published must be >= 1"
    );

    // Get version
    let version = gossip_get_version();
    assert!(!version.is_empty(), "version must not be empty");
    // Should be a semver-like string
    assert!(
        version.contains('.'),
        "version must contain a dot (semver)"
    );
}

// ── Test 10: Config parsing ───────────────────────────────────────────────────

#[test]
fn test_config_parsing() {
    use witan::config::GossipConfig;

    // Parse minimal config: {} — all defaults
    let minimal = GossipConfig::from_json("{}").expect("minimal config parse failed");
    let resolved = minimal.resolve().expect("minimal config resolve failed");
    assert_eq!(resolved.mesh_n, 8, "default mesh_n must be 8");
    assert_eq!(resolved.mesh_n_low, 4, "default mesh_n_low must be 4");
    assert_eq!(resolved.mesh_n_high, 12, "default mesh_n_high must be 12");
    assert_eq!(resolved.heartbeat_ms, 700, "default heartbeat_ms must be 700");
    assert_eq!(
        resolved.max_message_bytes, 1_048_576,
        "default max_message_bytes must be 1MB"
    );
    assert_eq!(
        resolved.dedup_cache_secs, 60,
        "default dedup_cache_secs must be 60"
    );
    assert!(
        (resolved.quorum_fraction - 0.67).abs() < 1e-9,
        "default quorum_fraction must be 0.67"
    );
    assert_eq!(
        resolved.replay_window_ms, 30_000,
        "default replay_window_ms must be 30000"
    );
    assert_eq!(resolved.default_ttl, 8, "default ttl must be 8");
    assert_eq!(
        resolved.key_epoch, "ephemeral-runtime",
        "default key_epoch must be ephemeral-runtime"
    );

    // Parse full config with all fields
    let full_json = r#"{
        "mesh_n": 6,
        "mesh_n_low": 3,
        "mesh_n_high": 10,
        "heartbeat_ms": 500,
        "max_message_bytes": 65536,
        "dedup_cache_secs": 120,
        "quorum_fraction": 0.75,
        "replay_window_ms": 15000,
        "default_ttl": 5,
        "key_epoch": "epoch-1"
    }"#;
    let full = GossipConfig::from_json(full_json).expect("full config parse failed");
    let resolved_full = full.resolve().expect("full config resolve failed");
    assert_eq!(resolved_full.mesh_n, 6);
    assert_eq!(resolved_full.mesh_n_low, 3);
    assert_eq!(resolved_full.mesh_n_high, 10);
    assert_eq!(resolved_full.heartbeat_ms, 500);
    assert_eq!(resolved_full.max_message_bytes, 65536);
    assert_eq!(resolved_full.dedup_cache_secs, 120);
    assert!((resolved_full.quorum_fraction - 0.75).abs() < 1e-9);
    assert_eq!(resolved_full.replay_window_ms, 15000);
    assert_eq!(resolved_full.default_ttl, 5);
    assert_eq!(resolved_full.key_epoch, "epoch-1");

    // Invalid config: mesh_n_low > mesh_n
    let invalid_json = r#"{"mesh_n": 4, "mesh_n_low": 8}"#;
    let invalid = GossipConfig::from_json(invalid_json).expect("parse should succeed");
    let err = invalid.resolve();
    assert!(err.is_err(), "mesh_n_low > mesh_n must return error");

    // Invalid config: quorum_fraction out of range
    let invalid_quorum = r#"{"quorum_fraction": 1.5}"#;
    let invalid_q = GossipConfig::from_json(invalid_quorum).expect("parse should succeed");
    let err_q = invalid_q.resolve();
    assert!(err_q.is_err(), "quorum_fraction > 1.0 must return error");

    // Invalid JSON
    let bad_json = "not json at all";
    let err_json = GossipConfig::from_json(bad_json);
    assert!(err_json.is_err(), "invalid JSON must return error");
}
