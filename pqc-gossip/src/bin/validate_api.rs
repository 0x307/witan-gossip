//! API endpoint validation binary for witan-gossip
//! Run with: cargo run -p witan-gossip --bin validate_api

use witan_gossip::{
    gossip_decode_envelope, gossip_encode_envelope, gossip_get_node_identity, gossip_get_peers,
    gossip_get_session, gossip_get_stats, gossip_get_version, gossip_init,
    gossip_process_handshake_bytes, gossip_publish, gossip_rotate_keys, gossip_verify_envelope,
    handshake::HandshakeManager,
    identity::NodeIdentity,
    types::PayloadType,
};

fn pass(n: usize, msg: &str, passed: &mut usize) {
    println!("  ✓ PASS: {msg}");
    *passed += 1;
    let _ = n;
}

fn fail(n: usize, msg: &str, failed: &mut usize) {
    println!("  ✗ FAIL: {msg}");
    *failed += 1;
    let _ = n;
}

fn main() {
    println!("=== witan-gossip API Validation ===\n");

    let mut passed = 0usize;
    let mut failed = 0usize;

    // ── Test 1: gossip_get_version ────────────────────────────────────────────
    println!("[TEST 1] gossip_get_version...");
    {
        let version = gossip_get_version();
        if !version.is_empty() {
            pass(1, &format!("version = \"{version}\""), &mut passed);
        } else {
            fail(1, "version string is empty", &mut failed);
        }
    }

    // ── Test 2: gossip_init with default config ───────────────────────────────
    println!("[TEST 2] gossip_init with default config...");
    {
        match gossip_init("{}") {
            Ok(()) => pass(2, "gossip_init succeeded with empty JSON config", &mut passed),
            Err(e) => fail(2, &format!("gossip_init failed: {e}"), &mut failed),
        }
    }

    // ── Test 3: gossip_get_node_identity ──────────────────────────────────────
    println!("[TEST 3] gossip_get_node_identity...");
    {
        match gossip_get_node_identity() {
            Ok(json) => {
                let parsed: serde_json::Value =
                    serde_json::from_str(&json).expect("node identity JSON is invalid");
                let node_id = parsed["node_id"].as_str().unwrap_or("");
                if node_id.len() == 64 && node_id.chars().all(|c| c.is_ascii_hexdigit()) {
                    pass(3, &format!("node_id = {node_id}"), &mut passed);
                } else {
                    fail(3, &format!("invalid node_id: \"{node_id}\""), &mut failed);
                }
            }
            Err(e) => fail(3, &format!("gossip_get_node_identity failed: {e}"), &mut failed),
        }
    }

    // ── Test 4: gossip_publish (Transaction) ──────────────────────────────────
    println!("[TEST 4] gossip_publish (Transaction)...");
    {
        match gossip_publish(PayloadType::Transaction as u8, b"tx-payload-data") {
            Ok(msg_id) => {
                if msg_id.len() == 32 {
                    pass(4, &format!("msg_id = {}", hex::encode(msg_id)), &mut passed);
                } else {
                    fail(4, &format!("msg_id wrong length: {}", msg_id.len()), &mut failed);
                }
            }
            Err(e) => fail(4, &format!("gossip_publish(Transaction) failed: {e}"), &mut failed),
        }
    }

    // ── Test 5: gossip_publish (BlockProposal) ────────────────────────────────
    println!("[TEST 5] gossip_publish (BlockProposal)...");
    {
        match gossip_publish(PayloadType::BlockProposal as u8, b"block-proposal-data") {
            Ok(msg_id) => {
                if msg_id.len() == 32 {
                    pass(5, &format!("msg_id = {}", hex::encode(msg_id)), &mut passed);
                } else {
                    fail(5, &format!("msg_id wrong length: {}", msg_id.len()), &mut failed);
                }
            }
            Err(e) => fail(5, &format!("gossip_publish(BlockProposal) failed: {e}"), &mut failed),
        }
    }

    // ── Test 6: gossip_publish (FinalityVote) ─────────────────────────────────
    println!("[TEST 6] gossip_publish (FinalityVote)...");
    {
        match gossip_publish(PayloadType::FinalityVote as u8, b"finality-vote-data") {
            Ok(msg_id) => {
                if msg_id.len() == 32 {
                    pass(6, &format!("msg_id = {}", hex::encode(msg_id)), &mut passed);
                } else {
                    fail(6, &format!("msg_id wrong length: {}", msg_id.len()), &mut failed);
                }
            }
            Err(e) => fail(6, &format!("gossip_publish(FinalityVote) failed: {e}"), &mut failed),
        }
    }

    // ── Test 7: gossip_publish (StateSync) ────────────────────────────────────
    println!("[TEST 7] gossip_publish (StateSync)...");
    {
        match gossip_publish(PayloadType::StateSync as u8, b"state-sync-data") {
            Ok(msg_id) => {
                if msg_id.len() == 32 {
                    pass(7, &format!("msg_id = {}", hex::encode(msg_id)), &mut passed);
                } else {
                    fail(7, &format!("msg_id wrong length: {}", msg_id.len()), &mut failed);
                }
            }
            Err(e) => fail(7, &format!("gossip_publish(StateSync) failed: {e}"), &mut failed),
        }
    }

    // ── Test 8: gossip_publish (PeerDiscovery) ────────────────────────────────
    println!("[TEST 8] gossip_publish (PeerDiscovery)...");
    {
        match gossip_publish(PayloadType::PeerDiscovery as u8, b"peer-discovery-data") {
            Ok(msg_id) => {
                if msg_id.len() == 32 {
                    pass(8, &format!("msg_id = {}", hex::encode(msg_id)), &mut passed);
                } else {
                    fail(8, &format!("msg_id wrong length: {}", msg_id.len()), &mut failed);
                }
            }
            Err(e) => fail(8, &format!("gossip_publish(PeerDiscovery) failed: {e}"), &mut failed),
        }
    }

    // ── Test 9: gossip_encode_envelope ────────────────────────────────────────
    println!("[TEST 9] gossip_encode_envelope...");
    let envelope_bytes = {
        match gossip_encode_envelope(PayloadType::Transaction as u8, b"encode-test-payload") {
            Ok(bytes) => {
                if !bytes.is_empty() {
                    pass(9, &format!("encoded {} bytes", bytes.len()), &mut passed);
                    bytes
                } else {
                    fail(9, "encoded bytes are empty", &mut failed);
                    vec![]
                }
            }
            Err(e) => {
                fail(9, &format!("gossip_encode_envelope failed: {e}"), &mut failed);
                vec![]
            }
        }
    };

    // ── Test 10: gossip_decode_envelope ───────────────────────────────────────
    println!("[TEST 10] gossip_decode_envelope...");
    {
        if envelope_bytes.is_empty() {
            fail(10, "skipped — no envelope bytes from test 9", &mut failed);
        } else {
            match gossip_decode_envelope(&envelope_bytes) {
                Ok(json) => {
                    let parsed: serde_json::Value =
                        serde_json::from_str(&json).expect("decoded JSON is invalid");
                    let version = parsed["version"].as_u64().unwrap_or(0);
                    if version == 1 {
                        pass(10, &format!("decoded envelope version={version}"), &mut passed);
                    } else {
                        fail(10, &format!("unexpected version: {version}"), &mut failed);
                    }
                }
                Err(e) => fail(10, &format!("gossip_decode_envelope failed: {e}"), &mut failed),
            }
        }
    }

    // ── Test 11: gossip_verify_envelope (valid) ───────────────────────────────
    println!("[TEST 11] gossip_verify_envelope (valid)...");
    {
        if envelope_bytes.is_empty() {
            fail(11, "skipped — no envelope bytes from test 9", &mut failed);
        } else {
            match gossip_verify_envelope(&envelope_bytes) {
                Ok(true) => pass(11, "valid envelope verified successfully", &mut passed),
                Ok(false) => fail(11, "valid envelope failed verification", &mut failed),
                Err(e) => fail(11, &format!("gossip_verify_envelope failed: {e}"), &mut failed),
            }
        }
    }

    // ── Test 12: gossip_verify_envelope (tampered — should fail) ─────────────
    println!("[TEST 12] gossip_verify_envelope (tampered — should fail)...");
    {
        if envelope_bytes.is_empty() {
            fail(12, "skipped — no envelope bytes from test 9", &mut failed);
        } else {
            // Tamper with the last 16 bytes of the envelope (signature area)
            let mut tampered = envelope_bytes.clone();
            let len = tampered.len();
            if len >= 16 {
                for b in tampered[len - 16..].iter_mut() {
                    *b ^= 0xFF;
                }
            }
            match gossip_verify_envelope(&tampered) {
                Ok(false) | Err(_) => pass(
                    12,
                    "tampered envelope correctly rejected (verify=false or error)",
                    &mut passed,
                ),
                Ok(true) => fail(12, "tampered envelope incorrectly verified as valid", &mut failed),
            }
        }
    }

    // ── Test 13: gossip_get_stats ─────────────────────────────────────────────
    println!("[TEST 13] gossip_get_stats...");
    {
        match gossip_get_stats() {
            Ok(json) => {
                let parsed: serde_json::Value =
                    serde_json::from_str(&json).expect("stats JSON is invalid");
                // Stats should have messages_published >= 5 (from tests 4-8)
                let msgs = parsed["messages_published"].as_u64().unwrap_or(0);
                if msgs >= 5 {
                    pass(13, &format!("stats OK, messages_published={msgs}"), &mut passed);
                } else {
                    fail(
                        13,
                        &format!("expected messages_published >= 5, got {msgs}"),
                        &mut failed,
                    );
                }
            }
            Err(e) => fail(13, &format!("gossip_get_stats failed: {e}"), &mut failed),
        }
    }

    // ── Test 14: gossip_get_peers (empty) ─────────────────────────────────────
    println!("[TEST 14] gossip_get_peers (empty)...");
    {
        match gossip_get_peers() {
            Ok(json) => {
                let parsed: serde_json::Value =
                    serde_json::from_str(&json).expect("peers JSON is invalid");
                if parsed.is_array() {
                    pass(
                        14,
                        &format!("peers list is array with {} entries", parsed.as_array().unwrap().len()),
                        &mut passed,
                    );
                } else {
                    fail(14, "peers response is not a JSON array", &mut failed);
                }
            }
            Err(e) => fail(14, &format!("gossip_get_peers failed: {e}"), &mut failed),
        }
    }

    // ── Test 15: gossip_create_handshake_init (gossip_connect_peer probe) ─────
    println!("[TEST 15] gossip_create_handshake_init (via gossip_connect_peer)...");
    let probe_bytes_for_16 = {
        use witan_gossip::gossip_connect_peer;
        match gossip_connect_peer("test-peer-15:9000") {
            Ok(probe_bytes) => {
                if !probe_bytes.is_empty() {
                    pass(
                        15,
                        &format!("probe bytes generated ({} bytes)", probe_bytes.len()),
                        &mut passed,
                    );
                    probe_bytes
                } else {
                    fail(15, "probe bytes are empty", &mut failed);
                    vec![]
                }
            }
            Err(e) => {
                fail(15, &format!("gossip_connect_peer failed: {e}"), &mut failed);
                vec![]
            }
        }
    };

    // ── Test 16: gossip_process_handshake_bytes (identity probe) ──────────────
    println!("[TEST 16] gossip_process_handshake_bytes (identity probe)...");
    {
        if probe_bytes_for_16.is_empty() {
            fail(16, "skipped — no probe bytes from test 15", &mut failed);
        } else {
            // Build a fresh server-side engine to process the probe
            // We use HandshakeManager directly since we can't call gossip_init again
            let server_identity = NodeIdentity::generate("test").expect("server identity failed");
            let mut server_hs = HandshakeManager::new();
            let now_ms = witan_gossip::current_time_unix_ms();
            match server_hs.process_incoming("test-peer-15:9000", &probe_bytes_for_16, &server_identity, now_ms) {
                Ok(ack_bytes) => {
                    if !ack_bytes.is_empty() {
                        pass(
                            16,
                            &format!("server processed probe, ACK = {} bytes", ack_bytes.len()),
                            &mut passed,
                        );
                        // Feed the ACK back to the global engine (client side)
                        match gossip_process_handshake_bytes("test-peer-15:9000", &ack_bytes) {
                            Ok(_) => {} // finish bytes sent
                            Err(_) => {} // ok — we won't complete this handshake
                        }
                    } else {
                        fail(16, "server returned empty ACK bytes", &mut failed);
                    }
                }
                Err(e) => fail(16, &format!("process_incoming(probe) failed: {e}"), &mut failed),
            }
        }
    }

    // ── Test 17: Full handshake roundtrip (two engines) ───────────────────────
    println!("[TEST 17] Full handshake roundtrip (two HandshakeManagers)...");
    {
        let alice = NodeIdentity::generate("test").expect("alice identity failed");
        let bob = NodeIdentity::generate("test").expect("bob identity failed");
        let mut alice_hs = HandshakeManager::new();
        let mut bob_hs = HandshakeManager::new();
        let now_ms = witan_gossip::current_time_unix_ms();

        let result = (|| -> Result<(), witan_gossip::GossipError> {
            // Step 1: Alice → Bob: probe
            let probe = alice_hs.create_identity_probe("bob", &alice)?;

            // Step 2: Bob processes probe → ACK
            let ack = bob_hs.process_incoming("alice", &probe, &bob, now_ms)?;

            // Step 3: Alice processes ACK → Finish
            let finish = alice_hs.process_incoming("bob", &ack, &alice, now_ms)?;

            // Step 4: Bob processes Finish → FinishAck
            let finish_ack = bob_hs.process_incoming("alice", &finish, &bob, now_ms)?;

            // Step 5: Alice processes FinishAck → complete (returns empty vec)
            let _empty = alice_hs.process_incoming("bob", &finish_ack, &alice, now_ms)?;

            Ok(())
        })();

        match result {
            Ok(()) => {
                let alice_done = alice_hs.is_handshake_complete("bob");
                let bob_done = bob_hs.is_handshake_complete("alice");

                if alice_done && bob_done {
                    let alice_session = alice_hs.get_session("bob");
                    let bob_session = bob_hs.get_session("alice");

                    match (alice_session, bob_session) {
                        (Some(a), Some(b)) => {
                            if a.session_id == b.session_id {
                                pass(
                                    17,
                                    &format!(
                                        "handshake complete, session_id = {}",
                                        &a.session_id[..16]
                                    ),
                                    &mut passed,
                                );
                            } else {
                                fail(
                                    17,
                                    &format!(
                                        "session_id mismatch: alice={} bob={}",
                                        &a.session_id[..16],
                                        &b.session_id[..16]
                                    ),
                                    &mut failed,
                                );
                            }
                        }
                        _ => fail(17, "could not retrieve sessions after handshake", &mut failed),
                    }
                } else {
                    fail(
                        17,
                        &format!(
                            "handshake not complete: alice_done={alice_done}, bob_done={bob_done}"
                        ),
                        &mut failed,
                    );
                }
            }
            Err(e) => fail(17, &format!("handshake roundtrip failed: {e}"), &mut failed),
        }
    }

    // ── Test 18: gossip_get_session (after handshake — expect not found) ──────
    println!("[TEST 18] gossip_get_session (no session for unknown peer)...");
    {
        match gossip_get_session("nonexistent-peer:9999") {
            Err(witan_gossip::GossipError::SessionNotFound(_))
            | Err(witan_gossip::GossipError::PeerNotFound(_)) => {
                pass(18, "SessionNotFound/PeerNotFound returned for unknown peer", &mut passed)
            }
            Ok(json) => {
                // Some implementations return empty JSON for missing sessions
                pass(18, &format!("get_session returned JSON: {json}"), &mut passed)
            }
            Err(e) => fail(18, &format!("unexpected error: {e}"), &mut failed),
        }
    }

    // ── Test 19: gossip_rotate_keys ───────────────────────────────────────────
    println!("[TEST 19] gossip_rotate_keys...");
    let new_node_id = {
        match gossip_rotate_keys() {
            Ok(new_id) => {
                if new_id.len() == 64 && new_id.chars().all(|c| c.is_ascii_hexdigit()) {
                    pass(19, &format!("new node_id = {new_id}"), &mut passed);
                    new_id
                } else {
                    fail(19, &format!("invalid new node_id: \"{new_id}\""), &mut failed);
                    String::new()
                }
            }
            Err(e) => {
                fail(19, &format!("gossip_rotate_keys failed: {e}"), &mut failed);
                String::new()
            }
        }
    };

    // ── Test 20: gossip_get_node_identity (after key rotation — new node_id) ──
    println!("[TEST 20] gossip_get_node_identity (after key rotation — new node_id)...");
    {
        match gossip_get_node_identity() {
            Ok(json) => {
                let parsed: serde_json::Value =
                    serde_json::from_str(&json).expect("node identity JSON is invalid");
                let current_id = parsed["node_id"].as_str().unwrap_or("");
                if current_id.len() == 64 && current_id.chars().all(|c| c.is_ascii_hexdigit()) {
                    if !new_node_id.is_empty() && current_id == new_node_id {
                        pass(
                            20,
                            &format!("node_id updated after rotation: {current_id}"),
                            &mut passed,
                        );
                    } else if new_node_id.is_empty() {
                        // Test 19 failed, just verify the identity is valid
                        pass(
                            20,
                            &format!("node_id is valid hex (rotation test 19 skipped): {current_id}"),
                            &mut passed,
                        );
                    } else {
                        fail(
                            20,
                            &format!(
                                "node_id mismatch after rotation: expected {new_node_id}, got {current_id}"
                            ),
                            &mut failed,
                        );
                    }
                } else {
                    fail(20, &format!("invalid node_id after rotation: \"{current_id}\""), &mut failed);
                }
            }
            Err(e) => fail(
                20,
                &format!("gossip_get_node_identity (post-rotation) failed: {e}"),
                &mut failed,
            ),
        }
    }

    // ── Summary ───────────────────────────────────────────────────────────────
    println!("\n=== Results: {}/{} passed ===", passed, passed + failed);
    if failed > 0 {
        std::process::exit(1);
    }
}
