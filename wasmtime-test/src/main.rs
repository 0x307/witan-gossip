//! Multi-instance wasmtime test harness for `witan`.
//!
//! Runs a 3-node gossip mesh entirely in-process using wasmtime.
//! Each node is an independent WASM instance with isolated linear memory.
//!
//! # Build the WASI binary first
//!
//! ```sh
//! cargo build -p witan --target wasm32-wasip1 --release
//! ```
//!
//! # Run the test
//!
//! ```sh
//! cargo run -p wasmtime-test -- target/wasm32-wasip1/release/witan.wasm
//! ```
//!
//! # Handshake protocol (host-driven I/O model)
//!
//! ```text
//! Node A (client)                    Node B (server)
//!   gossip_connect_peer("B") → probe_bytes
//!                               → send probe_bytes to B
//!                               B: gossip_process_handshake_bytes("A", probe_bytes) → ack_bytes
//!                               ← send ack_bytes to A
//!   A: gossip_process_handshake_bytes("B", ack_bytes) → finish_bytes
//!                               → send finish_bytes to B
//!                               B: gossip_process_handshake_bytes("A", finish_bytes) → finish_ack_bytes
//!                               ← send finish_ack_bytes to A
//!   A: gossip_process_handshake_bytes("B", finish_ack_bytes) → None (complete)
//!   SESSION ESTABLISHED on both sides
//! ```


mod node;

use anyhow::{Context, Result};
use node::GossipNode;
use wasmtime::Engine;

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Print a pass/fail banner for a test step.
macro_rules! check {
    ($label:expr, $result:expr) => {{
        match $result {
            Ok(v) => {
                println!("  ✓  {}", $label);
                v
            }
            Err(e) => {
                eprintln!("  ✗  {} — FAILED: {:#}", $label, e);
                std::process::exit(1);
            }
        }
    }};
}

/// Perform the full 4-message PQC handshake between two nodes.
///
/// `client` initiates; `server` responds.
/// After this function returns, both nodes have an established session.
fn do_handshake(client: &mut GossipNode, server: &mut GossipNode) -> Result<()> {
    let client_addr = client.addr.clone();
    let server_addr = server.addr.clone();

    // Step 1: client → probe
    let probe = client
        .connect_peer(&server_addr)
        .with_context(|| format!("{} connect_peer({})", client_addr, server_addr))?;

    // Step 2: server processes probe → ack
    let ack = server
        .process_handshake_bytes(&client_addr, &probe)
        .with_context(|| format!("{} process_handshake_bytes (probe)", server_addr))?
        .ok_or_else(|| anyhow::anyhow!("server returned None for probe — expected ack bytes"))?;

    // Step 3: client processes ack → finish
    let finish = client
        .process_handshake_bytes(&server_addr, &ack)
        .with_context(|| format!("{} process_handshake_bytes (ack)", client_addr))?
        .ok_or_else(|| anyhow::anyhow!("client returned None for ack — expected finish bytes"))?;

    // Step 4: server processes finish → finish_ack
    let finish_ack = server
        .process_handshake_bytes(&client_addr, &finish)
        .with_context(|| format!("{} process_handshake_bytes (finish)", server_addr))?
        .ok_or_else(|| {
            anyhow::anyhow!("server returned None for finish — expected finish_ack bytes")
        })?;

    // Step 5: client processes finish_ack → None (handshake complete)
    let done = client
        .process_handshake_bytes(&server_addr, &finish_ack)
        .with_context(|| format!("{} process_handshake_bytes (finish_ack)", client_addr))?;

    if done.is_some() {
        return Err(anyhow::anyhow!(
            "client returned Some bytes after finish_ack — expected None (handshake complete)"
        ));
    }

    Ok(())
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <path-to-wasm>", args[0]);
        eprintln!();
        eprintln!("Build the WASI binary first:");
        eprintln!("  cargo build -p witan --target wasm32-wasip1 --release");
        eprintln!("Then run:");
        eprintln!("  cargo run -p wasmtime-test -- target/wasm32-wasip1/release/witan.wasm");
        std::process::exit(1);
    }

    let wasm_path = &args[1];
    println!("Loading WASM from: {}", wasm_path);

    let wasm_bytes = std::fs::read(wasm_path)
        .with_context(|| format!("Failed to read WASM file: {}", wasm_path))?;

    // One Engine is shared across all instances (shares compiled code cache).
    let engine = Engine::default();

    println!();
    println!("══════════════════════════════════════════════════════════");
    println!("  witan  ·  3-node wasmtime integration test");
    println!("══════════════════════════════════════════════════════════");
    println!();

    // ── Step 0: Instantiate 3 nodes ───────────────────────────────────────────
    println!("[ 0 ] Instantiating 3 WASM nodes …");

    let mut node_a = check!(
        "instantiate node-a",
        GossipNode::new("node-a", &wasm_bytes, &engine)
    );
    let mut node_b = check!(
        "instantiate node-b",
        GossipNode::new("node-b", &wasm_bytes, &engine)
    );
    let mut node_c = check!(
        "instantiate node-c",
        GossipNode::new("node-c", &wasm_bytes, &engine)
    );

    // ── Step 1: Get version ───────────────────────────────────────────────────
    println!();
    println!("[ 1 ] Version check …");

    let ver_a = check!("node-a get_version", node_a.get_version());
    let ver_b = check!("node-b get_version", node_b.get_version());
    let ver_c = check!("node-c get_version", node_c.get_version());
    println!("      node-a: {}", ver_a);
    println!("      node-b: {}", ver_b);
    println!("      node-c: {}", ver_c);

    // ── Step 2: Initialize all 3 nodes ────────────────────────────────────────
    println!();
    println!("[ 2 ] Initializing nodes …");

    let config_a = serde_json::json!({
        "node_addr": "node-a",
        "max_peers": 16,
        "fanout": 3,
        "heartbeat_interval_ms": 1000,
        "message_ttl": 8,
        "replay_window_ms": 30000,
        "key_epoch": "epoch-1"
    })
    .to_string();

    let config_b = serde_json::json!({
        "node_addr": "node-b",
        "max_peers": 16,
        "fanout": 3,
        "heartbeat_interval_ms": 1000,
        "message_ttl": 8,
        "replay_window_ms": 30000,
        "key_epoch": "epoch-1"
    })
    .to_string();

    let config_c = serde_json::json!({
        "node_addr": "node-c",
        "max_peers": 16,
        "fanout": 3,
        "heartbeat_interval_ms": 1000,
        "message_ttl": 8,
        "replay_window_ms": 30000,
        "key_epoch": "epoch-1"
    })
    .to_string();

    check!("node-a gossip_init", node_a.init(&config_a));
    check!("node-b gossip_init", node_b.init(&config_b));
    check!("node-c gossip_init", node_c.init(&config_c));

    // ── Step 3: Print node identities ─────────────────────────────────────────
    println!();
    println!("[ 3 ] Node identities …");

    let id_a = check!("node-a get_node_identity", node_a.get_node_identity());
    let id_b = check!("node-b get_node_identity", node_b.get_node_identity());
    let id_c = check!("node-c get_node_identity", node_c.get_node_identity());

    println!("      node-a id: {}", id_a["node_id"].as_str().unwrap_or("?"));
    println!("      node-b id: {}", id_b["node_id"].as_str().unwrap_or("?"));
    println!("      node-c id: {}", id_c["node_id"].as_str().unwrap_or("?"));

    // ── Step 4: Handshake A ↔ B ───────────────────────────────────────────────
    println!();
    println!("[ 4 ] Handshake A ↔ B …");
    check!(
        "handshake node-a ↔ node-b",
        do_handshake(&mut node_a, &mut node_b)
    );

    // ── Step 5: Handshake A ↔ C ───────────────────────────────────────────────
    println!();
    println!("[ 5 ] Handshake A ↔ C …");
    check!(
        "handshake node-a ↔ node-c",
        do_handshake(&mut node_a, &mut node_c)
    );

    // ── Step 6: Handshake B ↔ C ───────────────────────────────────────────────
    println!();
    println!("[ 6 ] Handshake B ↔ C …");
    check!(
        "handshake node-b ↔ node-c",
        do_handshake(&mut node_b, &mut node_c)
    );

    // ── Step 7: Verify peer lists ─────────────────────────────────────────────
    println!();
    println!("[ 7 ] Verifying peer lists …");

    let peers_a = check!("node-a get_peers", node_a.get_peers());
    let peers_b = check!("node-b get_peers", node_b.get_peers());
    let peers_c = check!("node-c get_peers", node_c.get_peers());

    println!("      node-a peers: {}", peers_a.len());
    println!("      node-b peers: {}", peers_b.len());
    println!("      node-c peers: {}", peers_c.len());

    // node-a should see node-b and node-c
    if peers_a.len() < 2 {
        eprintln!("  ✗  node-a should have ≥2 peers, got {}", peers_a.len());
        std::process::exit(1);
    }
    println!("  ✓  node-a has ≥2 peers");

    // node-b should see node-a and node-c
    if peers_b.len() < 2 {
        eprintln!("  ✗  node-b should have ≥2 peers, got {}", peers_b.len());
        std::process::exit(1);
    }
    println!("  ✓  node-b has ≥2 peers");

    // node-c should see node-a and node-b
    if peers_c.len() < 2 {
        eprintln!("  ✗  node-c should have ≥2 peers, got {}", peers_c.len());
        std::process::exit(1);
    }
    println!("  ✓  node-c has ≥2 peers");

    // ── Step 8: Node A publishes a transaction ────────────────────────────────
    println!();
    println!("[ 8 ] Node A publishes a transaction …");

    let tx_payload = b"hello from node-a: test transaction payload";
    // payload_type 1 = Transaction (see PayloadType in types.rs)
    let msg_id = check!("node-a publish", node_a.publish(1, tx_payload));
    println!("      message_id: {}", hex::encode(msg_id));

    // ── Step 9: Encode envelope from A ───────────────────────────────────────
    println!();
    println!("[ 9 ] Encoding envelope from node-a …");

    let envelope_bytes = check!(
        "node-a encode_envelope",
        node_a.encode_envelope(1, tx_payload)
    );
    println!("      envelope size: {} bytes", envelope_bytes.len());

    // ── Step 10: Node B verifies the envelope ─────────────────────────────────
    println!();
    println!("[ 10 ] Node B verifies the envelope …");

    let b_valid = check!(
        "node-b verify_envelope",
        node_b.verify_envelope(&envelope_bytes)
    );
    if !b_valid {
        eprintln!("  ✗  node-b: envelope verification returned false");
        std::process::exit(1);
    }
    println!("  ✓  node-b: envelope is valid");

    // ── Step 11: Node C verifies the envelope ─────────────────────────────────
    println!();
    println!("[ 11 ] Node C verifies the envelope …");

    let c_valid = check!(
        "node-c verify_envelope",
        node_c.verify_envelope(&envelope_bytes)
    );
    if !c_valid {
        eprintln!("  ✗  node-c: envelope verification returned false");
        std::process::exit(1);
    }
    println!("  ✓  node-c: envelope is valid");

    // ── Step 12: Print stats from all nodes ───────────────────────────────────
    println!();
    println!("[ 12 ] Stats …");

    let stats_a = check!("node-a get_stats", node_a.get_stats());
    let stats_b = check!("node-b get_stats", node_b.get_stats());
    let stats_c = check!("node-c get_stats", node_c.get_stats());

    println!("      node-a: {}", serde_json::to_string_pretty(&stats_a).unwrap_or_default());
    println!("      node-b: {}", serde_json::to_string_pretty(&stats_b).unwrap_or_default());
    println!("      node-c: {}", serde_json::to_string_pretty(&stats_c).unwrap_or_default());

    // ── Step 13: Disconnect A from B ──────────────────────────────────────────
    println!();
    println!("[ 13 ] Disconnecting node-a from node-b …");

    check!("node-a disconnect_peer(node-b)", node_a.disconnect_peer("node-b"));

    // ── Step 14: Verify B no longer sees A ───────────────────────────────────
    println!();
    println!("[ 14 ] Verifying node-a no longer has node-b as peer …");

    let peers_a_after = check!("node-a get_peers (after disconnect)", node_a.get_peers());
    println!("      node-a peers after disconnect: {}", peers_a_after.len());

    let still_has_b = peers_a_after.iter().any(|p| {
        p.get("addr")
            .and_then(|v| v.as_str())
            .map(|s| s == "node-b")
            .unwrap_or(false)
    });
    if still_has_b {
        eprintln!("  ✗  node-a still lists node-b as a peer after disconnect");
        std::process::exit(1);
    }
    println!("  ✓  node-a no longer lists node-b");

    // ── Step 15: Final stats ──────────────────────────────────────────────────
    println!();
    println!("[ 15 ] Final stats …");

    let final_stats_a = check!("node-a final get_stats", node_a.get_stats());
    println!("      node-a: {}", serde_json::to_string_pretty(&final_stats_a).unwrap_or_default());

    // ── Done ──────────────────────────────────────────────────────────────────
    println!();
    println!("══════════════════════════════════════════════════════════");
    println!("  ALL TESTS PASSED ✓");
    println!("══════════════════════════════════════════════════════════");
    println!();

    Ok(())
}
