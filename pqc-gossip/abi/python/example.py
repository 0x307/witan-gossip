#!/usr/bin/env python3
"""
witan-gossip Python bindings — complete usage example.

Build the WASM binary first:
    cd pqc-gossip
    cargo build --target wasm32-unknown-unknown --release

Install dependencies:
    pip install -r requirements.txt

Run this example:
    python example.py [path/to/pqc_gossip.wasm]
"""

import json
import sys
from pathlib import Path

from gossip import GossipClient, GossipError


def main() -> None:
    # ── 1. Load the WASM component ────────────────────────────────────────────
    wasm_path = sys.argv[1] if len(sys.argv) > 1 else (
        "../../target/wasm32-unknown-unknown/release/pqc_gossip.wasm"
    )

    if not Path(wasm_path).exists():
        print(f"ERROR: WASM binary not found at {wasm_path}")
        print("Build it with: cargo build --target wasm32-unknown-unknown --release")
        sys.exit(1)

    print(f"Loading WASM component from: {wasm_path}")
    client = GossipClient(wasm_path=wasm_path)

    # ── 2. Get protocol version ───────────────────────────────────────────────
    version = client.get_version()
    print(f"Protocol version: {version}")

    # ── 3. Initialize with default config ────────────────────────────────────
    # Pass an empty dict or "{}" to use all defaults.
    config = {
        "mesh_n": 8,
        "mesh_n_low": 4,
        "mesh_n_high": 12,
        "heartbeat_ms": 700,
        "max_message_bytes": 1_048_576,
        "dedup_cache_secs": 60,
        "quorum_fraction": 0.67,
        "replay_window_ms": 30_000,
        "default_ttl": 8,
    }
    client.init(config)
    print("Gossip engine initialized.")

    # ── 4. Get node identity ──────────────────────────────────────────────────
    identity = client.get_node_identity()
    node_id = identity["node_id"]
    print(f"Node ID:    {node_id}")
    print(f"Key epoch:  {identity['key_epoch']}")
    print(f"SIG key:    {identity['sig_public_key_hex'][:32]}... ({len(identity['sig_public_key_hex'])//2} bytes)")

    # ── 5. Publish a transaction ──────────────────────────────────────────────
    tx_payload = b"example transaction payload bytes"
    msg_id = client.publish(0, tx_payload)  # 0 = Transaction
    print(f"\nPublished transaction:")
    print(f"  Message ID: {msg_id.hex()}")

    # ── 6. Publish a block proposal ───────────────────────────────────────────
    block_payload = b"block proposal: height=1000 validator=abc123"
    block_msg_id = client.publish(1, block_payload)  # 1 = BlockProposal
    print(f"Published block proposal:")
    print(f"  Message ID: {block_msg_id.hex()}")

    # ── 7. Publish a finality vote ────────────────────────────────────────────
    vote_payload = b"finality vote: round=5 block_hash=def456"
    vote_msg_id = client.publish(2, vote_payload)  # 2 = FinalityVote
    print(f"Published finality vote:")
    print(f"  Message ID: {vote_msg_id.hex()}")

    # ── 8. Encode an envelope for wire transmission ───────────────────────────
    envelope_bytes = client.encode_envelope(0, tx_payload)
    print(f"\nEncoded envelope: {len(envelope_bytes)} bytes")

    # ── 9. Decode the envelope back to a dict ─────────────────────────────────
    envelope = client.decode_envelope(envelope_bytes)
    print(f"Decoded envelope:")
    print(f"  version:      {envelope['version']}")
    print(f"  ttl:          {envelope['ttl']}")
    print(f"  payload_type: {envelope['payload_type']}")
    print(f"  sender:       {envelope['sender_node_id'][:16]}...")

    # ── 10. Verify the envelope ───────────────────────────────────────────────
    valid = client.verify_envelope(envelope_bytes)
    print(f"Envelope valid: {valid}")

    # Tamper with the envelope to test rejection
    tampered = bytearray(envelope_bytes)
    if len(tampered) > 50:
        tampered[50] ^= 0xFF
    try:
        tampered_valid = client.verify_envelope(bytes(tampered))
        print(f"Tampered envelope valid: {tampered_valid} (expected False)")
    except GossipError as e:
        print(f"Tampered envelope rejected with error: {e}")

    # ── 11. Get stats ─────────────────────────────────────────────────────────
    stats = client.get_stats()
    print(f"\nRuntime stats:")
    print(f"  messages_published:    {stats['messages_published']}")
    print(f"  messages_received:     {stats['messages_received']}")
    print(f"  messages_deduplicated: {stats['messages_deduplicated']}")
    print(f"  active_peers:          {stats['active_peers']}")
    print(f"  handshakes_completed:  {stats['handshakes_completed']}")

    # ── 12. Get connected peers ───────────────────────────────────────────────
    peers = client.get_peers()
    print(f"\nConnected peers: {len(peers)}")

    # ── 13. Simulate a peer handshake (client side) ───────────────────────────
    # In production, the host would:
    #   1. Call connect_peer() to get probe bytes
    #   2. Send probe bytes to the peer over the network
    #   3. Receive ACK bytes from the peer
    #   4. Call process_handshake_bytes() with the ACK
    #   5. Send the returned finish bytes to the peer
    #   6. Receive finish ACK bytes from the peer
    #   7. Call process_handshake_bytes() with the finish ACK
    #   8. Session is now established

    peer_addr = "192.168.1.10:9000"
    print(f"\nInitiating handshake with peer: {peer_addr}")
    try:
        probe_bytes = client.connect_peer(peer_addr)
        print(f"Handshake probe: {len(probe_bytes)} bytes (send to peer)")
        print(f"(In production: transmit probe_bytes to {peer_addr} and await ACK)")
    except GossipError as e:
        print(f"connect_peer error (expected in standalone test): {e}")

    # ── 14. Get current timestamp from WASM ──────────────────────────────────
    now_ms = client.now_ms()
    print(f"\nWASM timestamp: {now_ms} ms")

    # ── 15. Rotate keys ───────────────────────────────────────────────────────
    # WARNING: This invalidates all existing sessions.
    print("\nRotating keys...")
    new_node_id = client.rotate_keys()
    print(f"New node ID: {new_node_id}")
    assert new_node_id != node_id, "Node ID should change after key rotation"
    print("Key rotation verified: node ID changed.")

    # ── 16. Verify identity changed ───────────────────────────────────────────
    new_identity = client.get_node_identity()
    assert new_identity["node_id"] == new_node_id
    print(f"Identity confirmed: {new_identity['node_id'][:16]}...")

    print("\nAll examples completed successfully.")


# ─────────────────────────────────────────────────────────────────────────────
# Server-side handshake example
# ─────────────────────────────────────────────────────────────────────────────

def server_handshake_example(client: GossipClient, peer_addr: str, probe_bytes: bytes) -> None:
    """Demonstrates the server side of the 4-step PQC handshake.

    In production, probe_bytes arrives from the network.

    Args:
        client: An initialized GossipClient acting as the server.
        peer_addr: Network address of the client peer.
        probe_bytes: HandshakeProbe bytes received from the client.
    """
    # Step 2: Server receives probe, builds ACK
    ack_bytes = client.build_handshake_ack(peer_addr, probe_bytes)
    print(f"Built handshake ACK: {len(ack_bytes)} bytes")
    # → Send ack_bytes to the client peer

    # Step 4: Server receives finish probe, builds finish ACK
    # (finish_bytes arrives from the client after they process the ACK)
    finish_bytes = b""  # placeholder — arrives from network
    finish_ack_bytes = client.build_finish_ack(peer_addr, finish_bytes)
    print(f"Built finish ACK: {len(finish_ack_bytes)} bytes")
    # → Send finish_ack_bytes to the client peer
    # → Session is now established on both sides

    session = client.get_session(peer_addr)
    print(f"Session established: {json.dumps(session, indent=2)}")


# ─────────────────────────────────────────────────────────────────────────────
# Embedded bytes example
# ─────────────────────────────────────────────────────────────────────────────

def embedded_example() -> None:
    """Load the WASM binary from an embedded bytes variable.

    Useful for packaging the WASM binary inside a Python wheel.
    """
    # wasm_bytes = Path("pqc_gossip.wasm").read_bytes()
    # client = GossipClient(wasm_bytes=wasm_bytes)
    # client.init({})
    # print(f"Embedded WASM loaded. Version: {client.get_version()}")
    pass


if __name__ == "__main__":
    main()
