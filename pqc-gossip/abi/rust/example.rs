// pqc-gossip/abi/rust/example.rs
// Complete usage example for the witan-gossip Rust host bindings.
//
// Build the WASM binary first:
//   cd pqc-gossip
//   cargo build --target wasm32-unknown-unknown --release
//
// Then run this example:
//   cargo run --example gossip_example --features examples

use witan_gossip_abi::GossipClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── 1. Load the WASM component ────────────────────────────────────────────
    let wasm_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| {
            "../../target/wasm32-unknown-unknown/release/pqc_gossip.wasm".to_string()
        });

    println!("Loading WASM component from: {wasm_path}");
    let mut client = GossipClient::from_file(&wasm_path)?;

    // ── 2. Get protocol version ───────────────────────────────────────────────
    let version = client.get_version()?;
    println!("Protocol version: {version}");

    // ── 3. Initialize with default config ────────────────────────────────────
    // Pass "{}" to use all defaults, or provide a full config JSON.
    let config_json = serde_json::json!({
        "mesh_n": 8,
        "mesh_n_low": 4,
        "mesh_n_high": 12,
        "heartbeat_ms": 700,
        "max_message_bytes": 1048576,
        "dedup_cache_secs": 60,
        "quorum_fraction": 0.67,
        "replay_window_ms": 30000,
        "default_ttl": 8
    })
    .to_string();

    client.init(&config_json)?;
    println!("Gossip engine initialized.");

    // ── 4. Get node identity ──────────────────────────────────────────────────
    let identity_json = client.get_node_identity()?;
    let identity: serde_json::Value = serde_json::from_str(&identity_json)?;
    let node_id = identity["node_id"].as_str().unwrap_or("unknown");
    println!("Node ID: {node_id}");
    println!("Key epoch: {}", identity["key_epoch"].as_str().unwrap_or("unknown"));

    // ── 5. Publish a transaction ──────────────────────────────────────────────
    let tx_payload = b"example transaction payload bytes";
    let payload_type_transaction: u8 = 0;

    let msg_id = client.publish(payload_type_transaction, tx_payload)?;
    println!("Published transaction. Message ID: {}", hex::encode(msg_id));

    // ── 6. Encode an envelope for wire transmission ───────────────────────────
    let envelope_bytes = client.encode_envelope(payload_type_transaction, tx_payload)?;
    println!("Encoded envelope: {} bytes", envelope_bytes.len());

    // ── 7. Decode the envelope back to JSON ───────────────────────────────────
    let envelope_json = client.decode_envelope(&envelope_bytes)?;
    let envelope: serde_json::Value = serde_json::from_str(&envelope_json)?;
    println!(
        "Decoded envelope: version={}, ttl={}, payload_type={:?}",
        envelope["version"], envelope["ttl"], envelope["payload_type"]
    );

    // ── 8. Verify the envelope ────────────────────────────────────────────────
    let valid = client.verify_envelope(&envelope_bytes)?;
    println!("Envelope valid: {valid}");

    // ── 9. Publish a block proposal ───────────────────────────────────────────
    let block_payload = b"block proposal data: height=1000 hash=abc123";
    let payload_type_block: u8 = 1;
    let block_msg_id = client.publish(payload_type_block, block_payload)?;
    println!("Published block proposal. Message ID: {}", hex::encode(block_msg_id));

    // ── 10. Get stats ─────────────────────────────────────────────────────────
    let stats_json = client.get_stats()?;
    let stats: serde_json::Value = serde_json::from_str(&stats_json)?;
    println!(
        "Stats: published={}, received={}, active_peers={}",
        stats["messages_published"], stats["messages_received"], stats["active_peers"]
    );

    // ── 11. Simulate a peer handshake (client side) ───────────────────────────
    // In a real deployment, the host would:
    //   1. Call connect_peer() to get probe bytes
    //   2. Send probe bytes to the peer over the network
    //   3. Receive ACK bytes from the peer
    //   4. Call process_handshake_bytes() with the ACK
    //   5. Send the returned finish bytes to the peer
    //   6. Receive finish ACK bytes from the peer
    //   7. Call process_handshake_bytes() with the finish ACK
    //   8. Session is now established

    let peer_addr = "192.168.1.10:9000";
    println!("\nInitiating handshake with peer: {peer_addr}");

    match client.connect_peer(peer_addr) {
        Ok(probe_bytes) => {
            println!("Handshake probe: {} bytes (send to peer)", probe_bytes.len());
            println!("(In production: transmit probe_bytes to {peer_addr} and await ACK)");
        }
        Err(e) => {
            println!("connect_peer error (expected in standalone test): {e}");
        }
    }

    // ── 12. Get current peers ─────────────────────────────────────────────────
    let peers_json = client.get_peers()?;
    let peers: serde_json::Value = serde_json::from_str(&peers_json)?;
    let peer_count = peers.as_array().map(|a| a.len()).unwrap_or(0);
    println!("Connected peers: {peer_count}");

    // ── 13. Get current timestamp from WASM ──────────────────────────────────
    let now_ms = client.now_ms()?;
    println!("WASM timestamp: {now_ms} ms");

    // ── 14. Rotate keys ───────────────────────────────────────────────────────
    // WARNING: This invalidates all existing sessions.
    // Only do this in production when intentionally rotating.
    let new_node_id = client.rotate_keys()?;
    println!("Keys rotated. New node ID: {new_node_id}");

    // ── 15. Verify identity changed ───────────────────────────────────────────
    let new_identity_json = client.get_node_identity()?;
    let new_identity: serde_json::Value = serde_json::from_str(&new_identity_json)?;
    let new_id = new_identity["node_id"].as_str().unwrap_or("unknown");
    println!("Identity after rotation: {new_id}");
    assert_ne!(node_id, new_id, "Node ID should change after key rotation");

    println!("\nAll examples completed successfully.");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Server-side handshake example (separate function for clarity)
// ─────────────────────────────────────────────────────────────────────────────

/// Demonstrates the server side of the 4-step PQC handshake.
///
/// In production, `probe_bytes` arrives from the network.
#[allow(dead_code)]
fn server_handshake_example(
    client: &mut GossipClient,
    peer_addr: &str,
    probe_bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    // Step 2: Server receives probe, builds ACK
    let ack_bytes = client.build_handshake_ack(peer_addr, probe_bytes)?;
    println!("Built handshake ACK: {} bytes", ack_bytes.len());
    // → Send ack_bytes to the client peer

    // Step 4: Server receives finish probe, builds finish ACK
    // (finish_bytes arrives from the client after they process the ACK)
    let finish_bytes: Vec<u8> = vec![]; // placeholder — arrives from network
    let finish_ack_bytes = client.build_finish_ack(peer_addr, &finish_bytes)?;
    println!("Built finish ACK: {} bytes", finish_ack_bytes.len());
    // → Send finish_ack_bytes to the client peer
    // → Session is now established on both sides

    let session_json = client.get_session(peer_addr)?;
    println!("Session established: {session_json}");

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Embedded WASM bytes example
// ─────────────────────────────────────────────────────────────────────────────

/// Load the WASM binary at compile time using include_bytes!.
/// Useful for single-binary deployments.
#[allow(dead_code)]
fn embedded_example() -> Result<(), Box<dyn std::error::Error>> {
    // Uncomment and adjust path after building the WASM binary:
    // const WASM_BYTES: &[u8] = include_bytes!(
    //     "../../target/wasm32-unknown-unknown/release/pqc_gossip.wasm"
    // );
    // let mut client = GossipClient::from_bytes(WASM_BYTES)?;
    // client.init("{}")?;
    // println!("Embedded WASM loaded. Version: {}", client.get_version()?);
    Ok(())
}
