# witan-gossip

**The post-quantum-native gossip protocol engine for blockchains and mesh networks.**

[![Crates.io](https://img.shields.io/crates/v/witan-gossip.svg)](https://crates.io/crates/witan-gossip)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/0x307/witan-gossip)
[![Build Status](https://img.shields.io/github/actions/workflow/status/0x307/witan-gossip/ci.yml?branch=main)](https://github.com/0x307/witan-gossip/actions)
[![WASM Component](https://img.shields.io/badge/target-wasm32--wasip2-orange.svg)](https://webassembly.org/)
[![FIPS 203](https://img.shields.io/badge/FIPS-203%20ML--KEM--768-green.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![FIPS 204](https://img.shields.io/badge/FIPS-204%20ML--DSA--65-green.svg)](https://csrc.nist.gov/pubs/fips/204/final)

---

## Why this is different

Every gossip stack in production today — libp2p gossipsub, Tendermint/CometBFT P2P, raw NATS
fan-out — secures the **pipe** (TLS/Noise), not the **message**. The instant a message is relayed,
rebroadcast, or forwarded through a broker, that protection is gone: the next hop is a new session
trusting whatever the previous hop handed it.

`witan-gossip` signs the **envelope itself**. Every `GossipEnvelope` carries the sender's
post-quantum public key and an ML-DSA-65 signature over its own contents, so **any node, at any hop,
through any transport — including an untrusted relay or a public broker — can independently verify
who sent a message and when**, without re-establishing trust at every hop. Pair that with:

- **Post-quantum by default, not bolted on** — ML-KEM-768 + X25519 hybrid KEM (FIPS 203) and
  ML-DSA-65 (FIPS 204) are the baseline, with no classical-only code path to accidentally ship.
- **WASM Component Model portability** — one audited crypto core, embeddable in Rust, Go, Python,
  or behind a gRPC boundary, with no per-language PQC re-implementation risk.
- **A deliberately small, auditable core** — no sockets, no async runtime, no bundled transport
  stack inside the security-critical component.
- **BFT quorum, dedup, replay protection, and TTL hop-limiting** included out of the box.
- **Free and permissively licensed** (Apache-2.0 OR MIT) — no token, no vendor lock-in.

See [`docs/crates.io/comparison.md`](../docs/crates.io/comparison.md) for a full, honest look at how
this stacks up against libp2p, Tendermint P2P, and NATS, and
[`docs/crates.io/architecture.md`](../docs/crates.io/architecture.md) for why the layers below are
split the way they are.

---

## Overview

`witan-gossip` is a **production-grade, post-quantum cryptography (PQC) gossip protocol** implemented as a [WASM Component Model](https://component-model.bytecodealliance.org/) component for the **blockchain runtime**. It provides epidemic broadcast messaging with quantum-resistant cryptographic guarantees for validator-to-validator communication.

### What problem does it solve?

Classical gossip protocols used in blockchain networks rely on ECDH/ECDSA key exchange and signatures, which are vulnerable to Harvest-Now-Decrypt-Later (HNDL) attacks by quantum adversaries. `witan-gossip` replaces these with:

- **ML-KEM-768 + X25519 hybrid KEM** (NIST FIPS 203) for session key establishment
- **ML-DSA-65** (NIST FIPS 204) for message authentication and identity binding

The component is compiled to `wasm32-wasip2` and embedded in the blockchain host process. The **host owns transport** (QUIC/TCP/WebTransport, or a message broker such as NATS); the **component owns all cryptographic and protocol logic**. This separation means the PQC gossip layer can be upgraded independently of the transport layer.

### `witan-gossip` alone vs. a transport/messaging layer

| Capability | `witan-gossip` provides | A transport/messaging layer provides |
|---|---|---|
| Node identity, PQC handshake, session establishment | ✅ | — |
| Envelope signing & verification (ML-DSA-65) | ✅ | — |
| Deduplication, replay protection, TTL enforcement | ✅ | ⚠️ complementary at best |
| BFT quorum tracking | ✅ | — |
| Physical connectivity, socket lifecycle, fan-out | — | ✅ |
| Congestion control, NAT traversal, clustering | — | ✅ |
| Durable persistence / replay of missed messages | — | ✅ (e.g. JetStream-style streams) |

Neither layer replaces the other — see
[`docs/crates.io/architecture.md`](../docs/crates.io/architecture.md) for the full rationale and an
honest list of the risks this abstraction introduces.

### Who uses it?

- **Blockchain runtime validators** — for propagating transactions, block proposals, finality votes, and state sync data across the validator mesh
- **Blockchain host integrators** — any Rust/Go/Python host that embeds the WASM component via Wasmtime or another WASM runtime

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Blockchain Host Process                         │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                  Host Transport Layer                        │   │
│  │         (QUIC / TCP / WebTransport — host-owned)             │   │
│  │                                                              │   │
│  │   recv bytes ──────────────────────────────► send bytes      │   │
│  └──────────────────┬──────────────────────────────┬────────────┘   │
│                     │ WIT function calls           │ return bytes   │
│                     ▼                              │                │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │              WASM Component (witan-gossip)                   │   │
│  │                                                              │   │
│  │  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐     │   │
│  │  │  GossipAPI  │  │  Handshake   │  │  GossipEngine    │     │   │
│  │  │  (api.rs)   │  │  Manager     │  │  (gossip.rs)     │     │   │
│  │  └──────┬──────┘  │ (handshake   │  │                  │     │   │
│  │         │         │   .rs)       │  │  ┌────────────┐  │     │   │
│  │         │         └──────┬───────┘  │  │ DedupCache │  │     │   │
│  │         │                │          │  └────────────┘  │     │   │
│  │         └────────────────┴──────────►  ┌────────────┐  │     │   │
│  │                                     │  │  Quorum    │  │     │   │
│  │  ┌──────────────────────────────┐   │  │  Tracker   │  │     │   │
│  │  │       NodeIdentity           │   │  └────────────┘  │     │   │
│  │  │  kem_keypair: HybridKem      │   │  ┌────────────┐  │     │   │
│  │  │  sig_keypair: MlDsa65        │   │  │  Session   │  │     │   │
│  │  └──────────────────────────────┘   │  │  Store     │  │     │   │
│  │                                     │  └────────────┘  │     │   │
│  └─────────────────────────────────────┴──────────────────┘     │   │
│                     │                                               │
│                     ▼                                               │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │              PQC Cryptography Libraries                     │    │
│  │                                                             │    │
│  │   pqc-kem  (X25519 + ML-KEM-768 hybrid, FIPS 203)           │    │
│  │   pqc-sig  (ML-DSA-65, FIPS 204)                            │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

### Host-Driven I/O Model

The WASM component is **purely synchronous and stateless from the host's perspective**. The host:

1. Calls `gossip_connect_peer(addr)` → receives probe bytes
2. Transmits probe bytes over its transport
3. Receives response bytes from the peer
4. Calls `gossip_process_handshake_bytes(addr, bytes)` → receives next message bytes (or `None` when complete)
5. Repeats until handshake is complete
6. Calls `gossip_encode_envelope(type, payload)` → receives wire bytes to broadcast
7. Calls `gossip_verify_envelope(bytes)` on received envelopes

The component never initiates network I/O. All bytes flow through the WIT function boundary.

### 4-Message Handshake Flow

```
Client                                              Server
  │                                                    │
  │──[1] HandshakeProbe ──────────────────────────────►│
  │   magic: WITAN_GOSSIP_HANDSHAKE_V1                 │
  │   client_nonce: [u8; 32]                           │
  │   client_node_id: hex(SHA-256(kem_pk || sig_pk))   │
  │   timestamp_unix_ms: u64                           │
  │                                                    │
  │◄──[2] HandshakeAck ────────────────────────────────│
  │   magic: WITAN_GOSSIP_HANDSHAKE_ACK_V1             │
  │   client_nonce: echo                               │
  │   server_nonce: [u8; 32]                           │
  │   hybrid_kem_public_key_json: HybridPublicKey      │
  │   ml_dsa_65_public_key: [u8; 1952]                 │
  │   server_node_id: hex(SHA-256(kem_pk || sig_pk))   │
  │                                                    │
  │──[3] HandshakeFinish ─────────────────────────────►│
  │   magic: WITAN_GOSSIP_HANDSHAKE_FINISH_V1          │
  │   kem_ciphertext_json: HybridKemCiphertext         │
  │   client_ml_dsa_65_public_key: [u8; 1952]          │
  │   client_node_id: hex(SHA-256(kem_pk || sig_pk))   │
  │                                                    │
  │◄──[4] HandshakeFinishAck ──────────────────────────│
  │   magic: WITAN_GOSSIP_HANDSHAKE_FINISH_ACK_V1      │
  │   session_id: hex(HKDF-SHA256(...))                │
  │   transcript_hash: SHA-256(probe||ack||finish)     │
  │   server_mac: HMAC-SHA256(shared_secret, hash)     │
  │   transcript_signature: ML-DSA-65(transcript_hash) │
  │                                                    │
  │═══════════════ SESSION ESTABLISHED ════════════════│
```

---

## Cryptographic Guarantees

### Algorithms

| Role | Algorithm | Standard | Key/Output Size |
|------|-----------|----------|-----------------|
| Key Encapsulation | X25519 + ML-KEM-768 hybrid | NIST FIPS 203 | PK: 1184 B (ML-KEM) + 32 B (X25519); CT: ~1088 B + 32 B |
| Digital Signature | ML-DSA-65 (Dilithium3) | NIST FIPS 204 | PK: 1952 B; SK: 4000 B; Sig: 3309 B |
| Session ID Derivation | HKDF-SHA256 | RFC 5869 | 32-byte output |
| Server MAC | HMAC-SHA256 | RFC 2104 | 32-byte output |
| Message ID | SHA-256 | FIPS 180-4 | 32-byte output |
| Transcript Hash | SHA-256 | FIPS 180-4 | 32-byte output |
| Node ID | SHA-256(kem_pk \|\| sig_pk) | FIPS 180-4 | 32-byte → 64-char hex |

### What each algorithm provides

**ML-KEM-768 + X25519 Hybrid KEM (FIPS 203)**
- Establishes a shared secret between two nodes during the handshake
- The hybrid construction provides security if *either* X25519 or ML-KEM-768 is secure
- Protects against both classical and quantum adversaries (harvest-now-decrypt-later resistance)
- The shared secret is used as HKDF input material for session ID derivation

**ML-DSA-65 (FIPS 204)**
- Signs every `GossipEnvelope` to authenticate the sender
- Signs the handshake transcript to bind the session to the server's identity
- Context strings (`SIG_CTX_MESSAGE`, `SIG_CTX_HANDSHAKE`, `SIG_CTX_NODE_ID`) provide domain separation
- Signing input format: `0x00 || context_len_byte || context || message`

**HKDF-SHA256 Session ID**
- IKM = `shared_secret_32b || client_nonce_32b || server_nonce_32b || kem_ciphertext_bytes || node_id_bytes`
- Info = `b"pqc-kem-hybrid-v1"`
- Output = 32 bytes → 64-char hex session ID
- Binds the session to both parties' nonces and the KEM ciphertext, preventing session fixation

**HMAC-SHA256 Server MAC**
- `HMAC-SHA256(shared_secret_32b, transcript_hash)`
- Proves the server successfully decapsulated the KEM ciphertext (holds the shared secret)
- Verified by the client using constant-time comparison

---

## Gossip Protocol Mechanics

### Epidemic Broadcast

Messages are propagated using an **epidemic (gossip) broadcast** model. Each node forwards received messages to its mesh peers, minus the sender. The protocol converges to full network coverage in `O(log N)` rounds.

### Mesh Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `mesh_n` | 8 | Target mesh degree (number of peers to maintain) |
| `mesh_n_low` | 4 | Low watermark — graft new peers when below this |
| `mesh_n_high` | 12 | High watermark — prune peers when above this |
| `heartbeat_ms` | 700 ms | Interval for mesh maintenance and dedup eviction |

The mesh is maintained by the `GossipEngine::heartbeat()` method, which:
1. Evicts expired dedup cache entries
2. Cleans up timed-out handshakes (10-second timeout)
3. Prunes the quorum tracker
4. Grafts new peers if `mesh_peers.len() < mesh_n_low`

### Deduplication

Every received message is checked against a **SHA-256 keyed dedup cache** (`DedupCache`). The cache stores `message_id → insertion_timestamp_ms` with a configurable TTL (default: 60 seconds). Expired entries are lazily evicted on each `is_duplicate()` or `insert()` call.

### BFT Quorum

The `QuorumTracker` tracks acknowledgements per `message_id`. A message reaches quorum when:

```
ack_count >= ceil(total_peers × quorum_fraction)
```

With the default `quorum_fraction = 0.67` and 4 peers: `ceil(4 × 0.67) = ceil(2.68) = 3` acknowledgements required.

### TTL (Time-to-Live)

Each `GossipEnvelope` carries a `ttl: u8` field (default: 8). Forwarding nodes decrement TTL before re-broadcasting. Envelopes with `ttl == 0` are dropped and return `GossipError::TtlExpired`.

### Replay Protection

Envelopes are rejected if `|now_ms - timestamp_unix_ms| > replay_window_ms` (default: ±30 seconds). This prevents replay attacks where an adversary re-broadcasts old valid envelopes.

---

## Quick Start

### Minimal Rust usage (native)

```rust
use witan_gossip::{
    gossip_init, gossip_encode_envelope, gossip_verify_envelope,
    gossip_get_node_identity, gossip_publish, gossip_get_stats,
    types::PayloadType,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize with default configuration
    gossip_init("{}")?;

    // 2. Get this node's public identity
    let identity_json = gossip_get_node_identity()?;
    println!("Node identity: {}", identity_json);

    // 3. Publish a transaction to the gossip mesh
    //    Returns the 32-byte message ID
    let message_id = gossip_publish(
        PayloadType::Transaction as u8,
        b"my_transaction_bytes",
    )?;
    println!("Published message_id: {}", hex::encode(message_id));

    // 4. Encode a signed envelope for wire transmission
    let envelope_bytes = gossip_encode_envelope(
        PayloadType::BlockProposal as u8,
        b"block_proposal_data",
    )?;
    println!("Envelope size: {} bytes", envelope_bytes.len());

    // 5. Verify a received envelope
    let valid = gossip_verify_envelope(&envelope_bytes)?;
    assert!(valid, "envelope must verify");

    // 6. Get runtime statistics
    let stats_json = gossip_get_stats()?;
    println!("Stats: {}", stats_json);

    Ok(())
}
```

### Connecting to a peer

```rust
use witan_gossip::{
    gossip_init, gossip_connect_peer, gossip_process_handshake_bytes,
};

fn connect_to_peer(peer_addr: &str, transport: &mut dyn Transport) {
    gossip_init("{}").unwrap();

    // Step 1: Get probe bytes to send
    let probe_bytes = gossip_connect_peer(peer_addr).unwrap();
    transport.send(peer_addr, &probe_bytes);

    // Step 2-4: Drive the handshake exchange
    loop {
        let incoming = transport.recv(peer_addr);
        match gossip_process_handshake_bytes(peer_addr, &incoming).unwrap() {
            Some(response_bytes) => transport.send(peer_addr, &response_bytes),
            None => break, // Handshake complete
        }
    }
}
```

---

## API Reference

All public functions are re-exported from [`witan_gossip`](src/lib.rs) and correspond 1:1 to the WIT interface functions.

---

### `gossip_init`

```rust
pub fn gossip_init(config_json: &str) -> Result<(), GossipError>
```

Initialize the gossip component. Must be called **exactly once** before any other function. Calling it a second time returns `GossipError::AlreadyInitialized`.

**Parameters:**
- `config_json` — JSON string conforming to the [Configuration Schema](#configuration). Pass `"{}"` for all defaults.

**Returns:** `Ok(())` on success.

**Errors:**
- `GossipError::AlreadyInitialized` — called more than once
- `GossipError::ConfigError(String)` — invalid JSON or field value
- `GossipError::IdentityError(String)` — key generation failed

**Example:**
```rust
gossip_init(r#"{"mesh_n": 6, "default_ttl": 5}"#)?;
```

---

### `gossip_publish`

```rust
pub fn gossip_publish(payload_type: u8, payload: &[u8]) -> Result<[u8; 32], GossipError>
```

Publish a message to the gossip mesh. Builds a signed `GossipEnvelope`, checks the dedup cache, and returns the 32-byte message ID. The host is responsible for transmitting the encoded envelope to mesh peers via `gossip_encode_envelope`.

**Parameters:**
- `payload_type` — `u8` discriminant: `0`=Transaction, `1`=BlockProposal, `2`=FinalityVote, `3`=StateSync, `4`=PeerDiscovery
- `payload` — raw message bytes (max `max_message_bytes`, default 1 MB)

**Returns:** 32-byte `message_id = SHA-256(payload_type_byte || payload)`.

**Errors:**
- `GossipError::NotInitialized` — `gossip_init` not called
- `GossipError::InvalidInput(String)` — unknown `payload_type` or payload too large
- `GossipError::EnvelopeError(String)` — duplicate message (already in dedup cache)

**Example:**
```rust
let msg_id = gossip_publish(0, b"tx_data")?;
println!("message_id: {}", hex::encode(msg_id));
```

---

### `gossip_connect_peer`

```rust
pub fn gossip_connect_peer(peer_addr: &str) -> Result<Vec<u8>, GossipError>
```

Initiate a PQC handshake with a peer. Generates a `HandshakeProbe` (Message 1) and returns its bincode-encoded bytes for the host to transmit.

**Parameters:**
- `peer_addr` — network address string (e.g., `"192.168.1.10:9000"`)

**Returns:** Bincode-encoded `HandshakeProbe` bytes.

**Errors:**
- `GossipError::NotInitialized`
- `GossipError::HandshakeError(String)` — already connected to this peer

**Example:**
```rust
let probe_bytes = gossip_connect_peer("10.0.0.2:9000")?;
transport.send("10.0.0.2:9000", &probe_bytes);
```

---

### `gossip_disconnect_peer`

```rust
pub fn gossip_disconnect_peer(peer_addr: &str) -> Result<(), GossipError>
```

Disconnect from a peer and remove their session from the session store and mesh.

**Parameters:**
- `peer_addr` — network address of the peer to disconnect

**Returns:** `Ok(())` on success.

**Errors:**
- `GossipError::NotInitialized`
- `GossipError::PeerNotFound(String)` — no active session for this address

---

### `gossip_get_peers`

```rust
pub fn gossip_get_peers() -> Result<String, GossipError>
```

Get the list of currently connected peers as a JSON array.

**Returns:** JSON array of peer objects:
```json
[
  {
    "addr": "192.168.1.10:9000",
    "node_id": "a3f2...64-hex-chars",
    "session_id": "b7c1...64-hex-chars",
    "established_at_ms": 1724362000000
  }
]
```

**Errors:** `GossipError::NotInitialized`

---

### `gossip_get_node_identity`

```rust
pub fn gossip_get_node_identity() -> Result<String, GossipError>
```

Get this node's public identity as a JSON object.

**Returns:**
```json
{
  "node_id": "a3f2...64-hex-chars",
  "kem_public_key_json": "{\"x25519\":\"...\",\"mlkem\":\"...\"}",
  "sig_public_key_hex": "...3904-hex-chars...",
  "key_epoch": "ephemeral-runtime"
}
```

**Errors:** `GossipError::NotInitialized`, `GossipError::IdentityError(String)`

---

### `gossip_verify_envelope`

```rust
pub fn gossip_verify_envelope(envelope_bytes: &[u8]) -> Result<bool, GossipError>
```

Verify a received `GossipEnvelope` (bincode-encoded bytes). Performs all 6 checks in order.

**Parameters:**
- `envelope_bytes` — bincode-encoded `GossipEnvelope`

**Returns:** `true` if all checks pass.

**Verification checks (in order):**
1. `version == 1`
2. `message_id == SHA-256(payload_type_byte || payload)`
3. `|now_ms - timestamp_unix_ms| <= replay_window_ms`
4. `ttl > 0`
5. `payload.len() <= max_message_bytes`
6. ML-DSA-65 signature valid over `message_id || payload_type_byte || payload` with context `b"WITAN_GOSSIP_MESSAGE_V1"`

**Errors:**
- `GossipError::NotInitialized`
- `GossipError::SerializationError(String)` — bincode decode failed
- `GossipError::EnvelopeError(String)` — version mismatch, message_id mismatch, payload too large
- `GossipError::ReplayDetected` — timestamp outside replay window
- `GossipError::TtlExpired` — TTL is 0
- `GossipError::SignatureInvalid` — ML-DSA-65 verification failed

---

### `gossip_encode_envelope`

```rust
pub fn gossip_encode_envelope(payload_type: u8, payload: &[u8]) -> Result<Vec<u8>, GossipError>
```

Build a new signed `GossipEnvelope` and return its bincode-encoded bytes, ready for wire transmission.

**Parameters:**
- `payload_type` — `u8` discriminant (0–4)
- `payload` — raw message bytes

**Returns:** Bincode-encoded `GossipEnvelope` bytes.

**Errors:** `GossipError::NotInitialized`, `GossipError::InvalidInput(String)`, `GossipError::CryptoError(String)`

---

### `gossip_decode_envelope`

```rust
pub fn gossip_decode_envelope(bytes: &[u8]) -> Result<String, GossipError>
```

Decode a `GossipEnvelope` from bincode bytes to a JSON string. Signature bytes are hex-encoded in the output.

**Parameters:**
- `bytes` — bincode-encoded `GossipEnvelope`

**Returns:** JSON representation of all envelope fields.

**Errors:** `GossipError::NotInitialized`, `GossipError::SerializationError(String)`

---

### `gossip_get_stats`

```rust
pub fn gossip_get_stats() -> Result<String, GossipError>
```

Get runtime statistics as a JSON object. Also triggers a heartbeat (dedup eviction, mesh maintenance).

**Returns:**
```json
{
  "messages_published": 42,
  "messages_received": 137,
  "messages_deduplicated": 12,
  "messages_dropped": 3,
  "active_peers": 8,
  "mesh_peers": 8,
  "dedup_cache_size": 55,
  "handshakes_completed": 8,
  "handshakes_failed": 0
}
```

**Errors:** `GossipError::NotInitialized`

---

### `gossip_process_handshake_bytes`

```rust
pub fn gossip_process_handshake_bytes(
    peer_addr: &str,
    bytes: &[u8],
) -> Result<Option<Vec<u8>>, GossipError>
```

Process incoming handshake bytes from a peer. Automatically dispatches to the correct handler based on the magic prefix. Returns optional response bytes to send back, or `None` when the handshake is complete.

**Parameters:**
- `peer_addr` — network address of the sending peer
- `bytes` — raw bytes received from the peer

**Returns:** `Some(response_bytes)` if a response must be sent; `None` if the handshake is complete or no response is needed.

**Errors:** `GossipError::NotInitialized`, `GossipError::HandshakeError(String)`, `GossipError::CryptoError(String)`

---

### `gossip_build_handshake_ack`

```rust
pub fn gossip_build_handshake_ack(
    peer_addr: &str,
    probe_bytes: &[u8],
) -> Result<Vec<u8>, GossipError>
```

Build the server-side handshake ACK (Message 2 of 4). Called when acting as the server receiving a probe.

**Parameters:**
- `peer_addr` — address of the connecting client
- `probe_bytes` — bincode-encoded `HandshakeProbe` received from the client

**Returns:** Bincode-encoded `HandshakeAck` bytes to send back.

**Errors:** `GossipError::NotInitialized`, `GossipError::HandshakeError(String)`

---

### `gossip_build_finish_ack`

```rust
pub fn gossip_build_finish_ack(
    peer_addr: &str,
    finish_bytes: &[u8],
) -> Result<Vec<u8>, GossipError>
```

Build the server-side finish ACK (Message 4 of 4). Decapsulates the KEM ciphertext, computes the transcript hash and server MAC, signs the transcript, derives the session ID, and stores the completed session.

**Parameters:**
- `peer_addr` — address of the connecting client
- `finish_bytes` — bincode-encoded `HandshakeFinish` received from the client

**Returns:** Bincode-encoded `HandshakeFinishAck` bytes to send back.

**Errors:** `GossipError::NotInitialized`, `GossipError::HandshakeError(String)`, `GossipError::CryptoError(String)`

---

### `gossip_get_session`

```rust
pub fn gossip_get_session(peer_addr: &str) -> Result<String, GossipError>
```

Get session info for a specific peer as a JSON object.

**Returns:**
```json
{
  "session_id": "b7c1...64-hex-chars",
  "peer_addr": "192.168.1.10:9000",
  "peer_node_id": "a3f2...64-hex-chars",
  "established_at_ms": 1724362000000,
  "is_active": true
}
```

**Errors:** `GossipError::NotInitialized`, `GossipError::SessionNotFound(String)`

---

### `gossip_rotate_keys`

```rust
pub fn gossip_rotate_keys() -> Result<String, GossipError>
```

Rotate node identity keys. Generates a fresh ephemeral `NodeIdentity`. Existing sessions remain valid (they use the old keys for verification). New envelopes use the new keys.

**Returns:** New `node_id` as a 64-char hex string.

**Errors:** `GossipError::NotInitialized`, `GossipError::IdentityError(String)`

---

### `gossip_now_ms`

```rust
pub fn gossip_now_ms() -> u64
```

Get the current Unix timestamp in milliseconds. On WASM, uses WASI wall clock. On native, uses `std::time::SystemTime`.

**Returns:** Unix timestamp in milliseconds (no `Result` — infallible).

---

### `gossip_verify_signature`

```rust
pub fn gossip_verify_signature(
    public_key_bytes: &[u8],
    message: &[u8],
    signature: &[u8],
    context: &[u8],
) -> Result<bool, GossipError>
```

Verify a standalone ML-DSA-65 signature. Useful for the host to verify node identity claims independently of the gossip engine.

**Parameters:**
- `public_key_bytes` — ML-DSA-65 public key (1952 bytes)
- `message` — message bytes that were signed
- `signature` — ML-DSA-65 signature (3309 bytes)
- `context` — domain separation context (e.g., `b"WITAN_GOSSIP_MESSAGE_V1"`)

**Returns:** `true` if the signature is valid.

**Errors:** `GossipError::CryptoError(String)` — invalid key/signature format

---

### `gossip_get_version`

```rust
pub fn gossip_get_version() -> String
```

Get the component version string from `CARGO_PKG_VERSION`.

**Returns:** Version string (e.g., `"0.1.0"`). Infallible.

---

## Configuration

Pass a JSON object to `gossip_init`. All fields are optional; omitted fields use defaults.

```json
{
  "node_id":           null,
  "kem_seed_hex":      null,
  "sig_seed_hex":      null,
  "key_epoch":         "ephemeral-runtime",
  "mesh_n":            8,
  "mesh_n_low":        4,
  "mesh_n_high":       12,
  "heartbeat_ms":      700,
  "max_message_bytes": 1048576,
  "dedup_cache_secs":  60,
  "quorum_fraction":   0.67,
  "replay_window_ms":  30000,
  "default_ttl":       8
}
```

### Configuration Field Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `node_id` | `string \| null` | `null` | Optional node ID override. If `null`, derived as `hex(SHA-256(kem_pk \|\| sig_pk))`. |
| `kem_seed_hex` | `string \| null` | `null` | KEM seed as hex. Must be **192 hex chars** (96 bytes: 32 X25519 + 64 ML-KEM). If `null`, generates a fresh ephemeral keypair. |
| `sig_seed_hex` | `string \| null` | `null` | ML-DSA-65 seed as hex. Must be **64 hex chars** (32 bytes). If `null`, generates a fresh ephemeral keypair. |
| `key_epoch` | `string \| null` | `"ephemeral-runtime"` | Label for the key epoch. Informational only; included in identity JSON. |
| `mesh_n` | `u8 \| null` | `8` | Target mesh degree. Must satisfy `mesh_n_low ≤ mesh_n ≤ mesh_n_high`. |
| `mesh_n_low` | `u8 \| null` | `4` | Low watermark. Graft new peers when `mesh_peers.len() < mesh_n_low`. |
| `mesh_n_high` | `u8 \| null` | `12` | High watermark. Prune peers when `mesh_peers.len() >= mesh_n_high`. |
| `heartbeat_ms` | `u64 \| null` | `700` | Heartbeat interval in milliseconds. Used for dedup eviction and mesh maintenance. |
| `max_message_bytes` | `usize \| null` | `1048576` | Maximum payload size in bytes (1 MB). Envelopes exceeding this are dropped. |
| `dedup_cache_secs` | `u64 \| null` | `60` | Dedup cache TTL in seconds. Message IDs are evicted after this duration. |
| `quorum_fraction` | `f64 \| null` | `0.67` | BFT quorum fraction (0.0–1.0). Quorum requires `ceil(total_peers × fraction)` acks. |
| `replay_window_ms` | `u64 \| null` | `30000` | Replay protection window in milliseconds (±30 seconds). |
| `default_ttl` | `u8 \| null` | `8` | Default TTL hop count for new envelopes. |

### Validation Rules

- `mesh_n_low ≤ mesh_n ≤ mesh_n_high` — returns `GossipError::ConfigError` if violated
- `0.0 ≤ quorum_fraction ≤ 1.0` — returns `GossipError::ConfigError` if out of range
- `kem_seed_hex` must decode to exactly 96 bytes (192 hex chars)
- `sig_seed_hex` must decode to exactly 32 bytes (64 hex chars)

### Deterministic Node Identity (Configured Validators)

To restore a deterministic identity across restarts, provide both seeds:

```json
{
  "kem_seed_hex": "0102030405...192-hex-chars...",
  "sig_seed_hex": "0102030405...64-hex-chars...",
  "key_epoch": "validator-epoch-1"
}
```

The KEM seed layout: `[0..32]` = X25519 static secret, `[32..96]` = ML-KEM-768 seed.

---

## Message Types

The `PayloadType` enum discriminates gossip message payloads. The `u8` value is included in the `message_id` computation and the envelope wire format.

| Value | Variant | Description |
|-------|---------|-------------|
| `0` | `Transaction` | Blockchain transaction. Gossiped to all mesh peers. |
| `1` | `BlockProposal` | Block proposal from a validator. High priority. |
| `2` | `FinalityVote` | Finality vote from a validator. High priority. |
| `3` | `StateSync` | State synchronization data. May be large (up to `max_message_bytes`). |
| `4` | `PeerDiscovery` | Peer discovery advertisement. Payload contains `PeerInfo` JSON. |

Unknown discriminant values (5+) return `GossipError::InvalidInput`.

---

## Wire Format

### GossipEnvelope

The `GossipEnvelope` is the fundamental unit of gossip. It is serialized with **bincode** (compact, deterministic field order). Field order is fixed and must not change without a version bump.

```
GossipEnvelope (bincode):
┌─────────────────────────────────────────────────────────────────┐
│ version          : u8          (1 byte)   — always 1            │
│ message_id       : [u8; 32]   (32 bytes)  — SHA-256 hash        │
│ sender_node_id   : String     (variable)  — 64-char hex         │
│ sender_public_key: Vec<u8>    (1952 bytes)— ML-DSA-65 pub key   │
│ payload_type     : PayloadType (1 byte)   — u8 discriminant     │
│ payload          : Vec<u8>    (variable)  — raw app bytes       │
│ signature        : Vec<u8>    (3309 bytes)— ML-DSA-65 signature │
│ timestamp_unix_ms: u64        (8 bytes)   — Unix ms timestamp   │
│ ttl              : u8         (1 byte)    — hop count           │
└─────────────────────────────────────────────────────────────────┘
```

**Minimum envelope size** (empty payload): `1 + 32 + (8+64) + (8+1952) + 1 + (8+0) + (8+3309) + 8 + 1 ≈ 5,400 bytes`

**Typical envelope size** (256-byte payload): `≈ 5,656 bytes`

### message_id Computation

```
message_id = SHA-256(payload_type_byte || payload)
```

Where `payload_type_byte` is the single-byte `u8` discriminant of `PayloadType`.

### Signing Input

```
signing_input = message_id (32 bytes) || payload_type_byte (1 byte) || payload (N bytes)
```

The ML-DSA-65 signature is computed over `signing_input` with context string `b"WITAN_GOSSIP_MESSAGE_V1"`.

The full tagged message passed to ML-DSA-65 is:
```
0x00 || context_len_byte (1 byte) || context (23 bytes) || signing_input
```

### Bincode Encoding Notes

- `Vec<u8>` fields are encoded as `[u64 LE length][bytes...]`
- `String` fields are encoded as `[u64 LE length][utf8 bytes...]`
- `[u8; N]` arrays are encoded as raw bytes (no length prefix)
- `u8`, `u64` are encoded as little-endian

---

## PQC Handshake Protocol

### Overview

The handshake establishes a mutually authenticated session using:
- **X25519 + ML-KEM-768 hybrid KEM** for shared secret establishment
- **ML-DSA-65** for identity binding and transcript authentication
- **HKDF-SHA256** for session ID derivation
- **HMAC-SHA256** for server proof-of-possession

### Sequence Diagram

```
Client (Alice)                                    Server (Bob)
─────────────────────────────────────────────────────────────────
[1] build_probe()
    client_nonce ← random [u8; 32]
    probe = {magic, version=1, client_nonce,
             endpoint, client_node_id, timestamp}
    ──── HandshakeProbe (bincode) ──────────────────────────────►

                                          [2] process_probe_build_ack()
                                              server_nonce ← random [u8; 32]
                                              ack = {magic, version=1,
                                                     client_nonce (echo),
                                                     server_nonce,
                                                     hybrid_kem_public_key_json,
                                                     ml_dsa_65_public_key,
                                                     server_node_id, timestamp}
    ◄─── HandshakeAck (bincode) ────────────────────────────────

[3] process_ack_build_finish()
    Verify: client_nonce echo matches
    Verify: server sig pk size == 1952 bytes
    Parse server KEM public key from JSON
    (ciphertext, shared_secret) ← KEM.encapsulate(server_kem_pk)
    shared_secret_32b ← shared_secret.as_32_bytes()
    finish = {magic, version=1,
              kem_ciphertext_json,
              client_ml_dsa_65_public_key,
              client_node_id, timestamp}
    ──── HandshakeFinish (bincode) ─────────────────────────────►

                                          [4] process_finish_build_finish_ack()
                                              shared_secret ← KEM.decapsulate(ciphertext)
                                              shared_secret_32b ← shared_secret.as_32_bytes()
                                              transcript_hash = SHA-256(probe||ack||finish)
                                              server_mac = HMAC-SHA256(shared_secret_32b,
                                                                        transcript_hash)
                                              transcript_sig = ML-DSA-65.sign(
                                                  transcript_hash,
                                                  ctx=b"WITAN_GOSSIP_HANDSHAKE_V1")
                                              session_id = HKDF-SHA256(
                                                  ikm=shared_secret_32b||client_nonce||
                                                      server_nonce||kem_ct_bytes||node_id,
                                                  info=b"pqc-kem-hybrid-v1",
                                                  len=32)
                                              finish_ack = {magic, version=1,
                                                            session_id, transcript_hash,
                                                            server_mac, transcript_sig,
                                                            timestamp}
                                              ── SESSION ESTABLISHED (server) ──
    ◄─── HandshakeFinishAck (bincode) ──────────────────────────

[5] process_finish_ack()
    Recompute transcript_hash = SHA-256(probe||ack||finish)
    Verify: transcript_hash matches
    Recompute server_mac; verify (constant-time)
    Verify: ML-DSA-65 transcript_sig with server's sig pk
    ── SESSION ESTABLISHED (client) ──
─────────────────────────────────────────────────────────────────
```

### Session ID Derivation Formula

```
IKM  = shared_secret_32b (32 bytes)
     || client_nonce (32 bytes)
     || server_nonce (32 bytes)
     || kem_ciphertext_bytes (variable, bincode-encoded HybridKemCiphertext)
     || node_id_bytes (64 bytes, UTF-8 hex string)

HKDF-SHA256(IKM, salt=None, info=b"pqc-kem-hybrid-v1", len=32)
→ session_id_bytes (32 bytes)
→ session_id = hex::encode(session_id_bytes)  // 64-char hex string
```

Both client and server derive the same `session_id` because they share the same `shared_secret_32b` (from KEM encapsulate/decapsulate), the same nonces (echoed in the ACK), and the same ciphertext bytes.

### Transcript Hash

```
transcript_hash = SHA-256(probe_bytes || ack_bytes || finish_bytes)
```

Where each `*_bytes` is the full bincode-encoded message as transmitted on the wire.

### Server MAC

```
server_mac = HMAC-SHA256(key=shared_secret_32b, data=transcript_hash)
```

The client verifies this using **constant-time comparison** to prevent timing attacks.

### Handshake Timeout

Pending handshakes time out after **10 seconds**. Timed-out handshakes are evicted during `heartbeat()` and counted in `handshakes_failed`.

### Magic Byte Constants

| Message | Magic Bytes | Length |
|---------|-------------|--------|
| `HandshakeProbe` | `b"WITAN_GOSSIP_HANDSHAKE_V1"` | 25 bytes |
| `HandshakeAck` | `b"WITAN_GOSSIP_HANDSHAKE_ACK_V1"` | 29 bytes |
| `HandshakeFinish` | `b"WITAN_GOSSIP_HANDSHAKE_FINISH_V1"` | 32 bytes |
| `HandshakeFinishAck` | `b"WITAN_GOSSIP_HANDSHAKE_FINISH_ACK_V1"` | 36 bytes |

Incoming bytes are classified by reading bytes `[8..]` (skipping the 8-byte bincode `Vec<u8>` length prefix) and matching against these magic constants. Longest-prefix matching is used to avoid collisions between `HANDSHAKE_FINISH` and `HANDSHAKE_FINISH_ACK`.

---

## WIT Interface

The component is defined by the WIT world `witan:gossip/gossip-world@0.1.0` in [`pqc-gossip/wit/gossip-protocol.wit`](wit/gossip-protocol.wit).

### World Definition

```wit
package witan:gossip@0.1.0;

world gossip-world {
    export gossip-protocol;
}
```

The component **exports** the `gossip-protocol` interface. Its WASI **imports**
are not declared in the world: on `wasm32-wasip2` the Rust standard library
supplies them and they appear in the emitted component automatically. The
build depends on three of them —

- `wasi:clocks/wall-clock` — Unix timestamps in envelopes
- `wasi:clocks/monotonic-clock` — handshake timeout tracking
- `wasi:random/random` — nonce and key generation

— alongside the `wasi:cli`/`wasi:io` interfaces std pulls in. Read the real,
current import set off the artifact rather than trusting this list:

```bash
wasm-tools component wit target/wasm32-wasip2/release/witan_gossip.wasm
```

### Using with `cargo component`

```bash
# Install cargo-component
cargo install cargo-component

# Build the WASM component
cargo component build -p witan-gossip --release

# The component is at:
# target/wasm32-wasip1/release/witan_gossip.wasm
```

### Using with `wasmtime` CLI

```bash
# Run a WIT function directly (for testing)
wasmtime run --wasm component-model \
  target/wasm32-wasip2/release/witan_gossip.wasm \
  --invoke gossip-now-ms
```

### WIT Function Signatures

```wit
interface gossip-protocol {
    gossip-init: func(config-json: string) -> result<_, gossip-error>;
    gossip-publish: func(payload-type-id: u8, payload: list<u8>) -> result<list<u8>, gossip-error>;
    gossip-connect-peer: func(peer-addr: string) -> result<list<u8>, gossip-error>;
    gossip-disconnect-peer: func(peer-addr: string) -> result<_, gossip-error>;
    gossip-get-peers: func() -> result<string, gossip-error>;
    gossip-get-session: func(peer-addr: string) -> result<string, gossip-error>;
    gossip-get-node-identity: func() -> result<string, gossip-error>;
    gossip-rotate-keys: func() -> result<string, gossip-error>;
    gossip-verify-envelope: func(envelope-bytes: list<u8>) -> result<bool, gossip-error>;
    gossip-encode-envelope: func(payload-type-id: u8, payload: list<u8>) -> result<list<u8>, gossip-error>;
    gossip-decode-envelope: func(bytes: list<u8>) -> result<string, gossip-error>;
    gossip-get-stats: func() -> result<string, gossip-error>;
    gossip-process-handshake-bytes: func(peer-addr: string, bytes: list<u8>) -> result<option<list<u8>>, gossip-error>;
    gossip-build-handshake-ack: func(peer-addr: string, probe-bytes: list<u8>) -> result<list<u8>, gossip-error>;
    gossip-build-finish-ack: func(peer-addr: string, finish-bytes: list<u8>) -> result<list<u8>, gossip-error>;
    gossip-now-ms: func() -> u64;
    gossip-verify-signature: func(public-key-bytes: list<u8>, message: list<u8>, signature: list<u8>, context: list<u8>) -> result<bool, gossip-error>;
    gossip-get-version: func() -> string;
}
```

All 18 functions map 1:1 onto the public functions in
[`src/api.rs`](src/api.rs) and are exported by the built component; verify with
`wasm-tools component wit` rather than taking this listing on trust.

---

## Building

### Prerequisites

- **Rust** 1.82+ (2021 edition; `wasm32-wasip2` requires 1.82)
- **`wasm32-wasip2` target** for component builds

```bash
rustup target add wasm32-wasip2
```

`cargo-component` is optional — needed only for the alternative build path below.

### Native Build

```bash
cargo build -p witan-gossip
```

### WASM Component Build (optimized for size)

```bash
cargo build -p witan-gossip \
  --target wasm32-wasip2 \
  --release
```

This emits a WASM Component directly at
`target/wasm32-wasip2/release/witan_gossip.wasm` — no adapter or post-processing
step. Confirm what you built:

```bash
wasm-tools component wit target/wasm32-wasip2/release/witan_gossip.wasm
# world root { … export witan:gossip/gossip-protocol@0.1.0; }
```

The release profile is configured for minimum WASM size:

```toml
[profile.release]
opt-level = "z"      # optimize for size
lto = true           # link-time optimization
codegen-units = 1    # single codegen unit for better LTO
panic = "abort"      # no unwinding in WASM
strip = true         # strip debug symbols
```

### Alternative: `cargo component`

```bash
cargo install cargo-component
cargo component build -p witan-gossip --release
# Output: target/wasm32-wasip1/release/witan_gossip.wasm
```

This builds a `wasm32-wasip1` core module and componentizes it with an adapter.
The result exports the same `witan:gossip/gossip-protocol@0.1.0` interface as the
`wasm32-wasip2` build. Both paths are exercised in CI; pick whichever fits your
toolchain. Note that `cargo component build` regenerates `src/bindings.rs`, which
this crate does not use (guest bindings come from `wit_bindgen::generate!` in
`src/component.rs`) and which is gitignored as a build artifact.

### Unsupported targets

`wasm32-unknown-unknown` is not supported. It provides no WASI wall clock, so
rather than compiling and then panicking at runtime, the crate deliberately fails
to build there.

### Feature Flags

| Feature | Description |
|---------|-------------|
| `wasi-abi` | **Deprecated.** Legacy hand-rolled ptr/len C-ABI (`gossip_*_wasi`) for `wasm32-wasip1` core-module hosts, superseded by the component interface. Off by default; retained for pre-existing consumers and scheduled for removal. |
| `native-transport` | Enable native QUIC/TCP transport (Quinn, Rustls, Tokio) for integration tests |

---

## Integration Guide

### Wasmtime (Rust Host) Example

```rust
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::WasiCtxBuilder;

fn main() -> anyhow::Result<()> {
    // Configure Wasmtime with Component Model support
    let mut config = Config::new();
    config.wasm_component_model(true);
    let engine = Engine::new(&config)?;

    // Load the compiled WASM component
    let component = Component::from_file(
        &engine,
        "target/wasm32-wasip2/release/witan_gossip.wasm",
    )?;

    // Set up WASI context (provides clocks and random)
    let wasi = WasiCtxBuilder::new().build();
    let mut store = Store::new(&engine, wasi);

    // Link WASI interfaces
    let mut linker = Linker::new(&engine);
    wasmtime_wasi::add_to_linker_sync(&mut linker)?;

    // Instantiate the component
    let instance = linker.instantiate(&mut store, &component)?;

    // Call gossip-init
    let gossip_init = instance.get_typed_func::<(String,), (Result<(), _>,)>(
        &mut store, "gossip-init"
    )?;
    gossip_init.call(&mut store, (r#"{"mesh_n": 8}"#.to_string(),))?;

    // Encode an envelope
    let gossip_encode = instance.get_typed_func::<(u8, Vec<u8>), (Result<Vec<u8>, _>,)>(
        &mut store, "gossip-encode-envelope"
    )?;
    let (result,) = gossip_encode.call(
        &mut store,
        (0u8, b"my_transaction".to_vec()),
    )?;
    let envelope_bytes = result.unwrap();
    println!("Envelope: {} bytes", envelope_bytes.len());

    Ok(())
}
```

### Host-Driven Transport Model

The component never initiates network I/O. The host is responsible for:

1. **Accepting connections** — when a peer connects, the host receives bytes and routes them to `gossip_process_handshake_bytes`
2. **Initiating connections** — the host calls `gossip_connect_peer` to get probe bytes, then sends them
3. **Broadcasting envelopes** — after `gossip_publish`, the host calls `gossip_encode_envelope` and sends the bytes to all mesh peers
4. **Receiving envelopes** — the host passes received bytes to `gossip_verify_envelope` before processing

### Handling the Handshake Exchange

```rust
// Server side: handle incoming connection
fn handle_incoming_connection(
    peer_addr: &str,
    initial_bytes: &[u8],
    transport: &mut dyn Transport,
) {
    // Route to handshake processor
    match gossip_process_handshake_bytes(peer_addr, initial_bytes).unwrap() {
        Some(ack_bytes) => {
            // Send ACK back to client
            transport.send(peer_addr, &ack_bytes);
        }
        None => {
            // Handshake complete (shouldn't happen on first message)
        }
    }
}

// Client side: initiate connection
fn initiate_connection(peer_addr: &str, transport: &mut dyn Transport) {
    // Get probe bytes
    let probe = gossip_connect_peer(peer_addr).unwrap();
    transport.send(peer_addr, &probe);

    // Drive the handshake to completion
    loop {
        let response = transport.recv(peer_addr);
        match gossip_process_handshake_bytes(peer_addr, &response).unwrap() {
            Some(next_msg) => transport.send(peer_addr, &next_msg),
            None => break, // Handshake complete
        }
    }
}
```

### Publishing and Receiving Gossip Messages

```rust
// Publishing
fn publish_transaction(tx_bytes: &[u8], mesh_peers: &[String], transport: &mut dyn Transport) {
    // Register with dedup cache and get message_id
    let _msg_id = gossip_publish(0 /* Transaction */, tx_bytes).unwrap();

    // Encode the signed envelope
    let envelope_bytes = gossip_encode_envelope(0, tx_bytes).unwrap();

    // Host broadcasts to all mesh peers
    for peer in mesh_peers {
        transport.send(peer, &envelope_bytes);
    }
}

// Receiving
fn handle_received_envelope(bytes: &[u8]) -> bool {
    match gossip_verify_envelope(bytes) {
        Ok(true) => {
            // Valid envelope — decode and process
            let json = gossip_decode_envelope(bytes).unwrap();
            println!("Received: {}", json);
            true
        }
        Ok(false) => false,
        Err(e) => {
            eprintln!("Envelope rejected: {:?}", e);
            false
        }
    }
}
```

---

## ABI Bindings

Language bindings for the WIT interface are planned in `pqc-gossip/abi/`:

| Language | Binding Type | Status |
|----------|-------------|--------|
| **Rust** | Native `rlib` (direct crate dependency) | ✅ Available |
| **Go** | `wit-bindgen-go` generated bindings | 🔜 Planned |
| **Python** | `componentize-py` bindings | 🔜 Planned |
| **gRPC/Protobuf** | Host-side gRPC proxy over WASM | 🔜 Planned |

For Rust hosts, use the crate directly as an `rlib` dependency. For other languages, embed the WASM component in a Wasmtime host and use the generated WIT bindings.

---

## Testing

### Running the Integration Tests

```bash
# Run all 10 integration tests
cargo test -p witan-gossip

# Run with output
cargo test -p witan-gossip -- --nocapture

# Run a specific test
cargo test -p witan-gossip test_handshake_full_roundtrip -- --nocapture
```

### Test Suite

The integration tests in [`pqc-gossip/tests/integration_tests.rs`](tests/integration_tests.rs) cover:

| # | Test Name | What It Tests |
|---|-----------|---------------|
| 1 | `test_node_identity_generate` | Random identity generation; `node_id` is 64-char hex; ML-DSA-65 public key is 1952 bytes (3904 hex chars) |
| 2 | `test_node_identity_from_seeds` | Deterministic identity from seeds; same seeds → same `node_id` |
| 3 | `test_sign_and_verify` | ML-DSA-65 sign/verify roundtrip; wrong message → `false`; wrong context → `false` |
| 4 | `test_envelope_roundtrip` | `gossip_encode_envelope` → `gossip_decode_envelope` → `gossip_verify_envelope`; checks all JSON fields |
| 5 | `test_envelope_replay_detection` | Envelope with timestamp 60s in the past returns `GossipError::ReplayDetected` |
| 6 | `test_dedup_cache` | Insert/lookup/TTL eviction; expired entries are removed after TTL |
| 7 | `test_quorum_tracker` | `ceil(0.67 × 4) = 3` acks required; duplicate acks from same peer don't double-count |
| 8 | `test_handshake_full_roundtrip` | Full 4-message handshake between Alice and Bob; session IDs match on both sides |
| 9 | `test_full_api_integration` | `gossip_init` → `gossip_get_node_identity` → `gossip_publish` → `gossip_get_stats` → `gossip_get_version` |
| 10 | `test_config_parsing` | Default values; full config; invalid `mesh_n_low > mesh_n`; invalid `quorum_fraction > 1.0`; invalid JSON |

### Global State Note

`gossip_init` uses `OnceLock` — it can only succeed once per process. Tests that require the global engine share a single initialization via `std::sync::Once`. Tests that don't need the global engine (tests 1–3, 5–8, 10) create their own local instances.

---

## Security Model

### Threat Model

`witan-gossip` is designed to protect against:

| Threat | Mitigation |
|--------|-----------|
| **Quantum adversary (HNDL)** | ML-KEM-768 + X25519 hybrid KEM; ML-DSA-65 signatures |
| **Message forgery** | Every envelope is ML-DSA-65 signed; `sender_public_key` is embedded in the envelope |
| **Replay attacks** | `timestamp_unix_ms` checked against ±30s window; `message_id` in dedup cache |
| **Session fixation** | Session ID derived from both nonces + KEM ciphertext + node ID via HKDF |
| **Man-in-the-middle** | Server MAC proves KEM decapsulation; ML-DSA-65 transcript signature binds identity |
| **Sybil attacks** | Node ID = `SHA-256(kem_pk || sig_pk)`; changing identity requires new keypairs |
| **Eclipse attacks** | Mesh degree limits (D_low=4, D_high=12) prevent single-peer dominance |
| **Amplification / flooding** | TTL hop limit (default 8); dedup cache prevents re-broadcast of seen messages |
| **Oversized payloads** | `max_message_bytes` limit (default 1 MB) enforced at publish and verify |
| **Timing attacks** | Server MAC verified with constant-time comparison |

### What PQC Protects Against

The hybrid KEM (X25519 + ML-KEM-768) provides **harvest-now-decrypt-later** resistance. An adversary who records encrypted handshake traffic today cannot decrypt it in the future using a quantum computer, because ML-KEM-768 is secure against Grover's and Shor's algorithms.

ML-DSA-65 provides **quantum-resistant authentication**. Classical ECDSA signatures can be forged by a quantum adversary with a sufficiently powerful quantum computer; ML-DSA-65 (based on the hardness of Module-LWE) cannot.

### Replay Protection Details

- **Envelope replay**: `|now_ms - envelope.timestamp_unix_ms| > replay_window_ms` → `GossipError::ReplayDetected`
- **Dedup cache**: `message_id` stored for `dedup_cache_secs` (default 60s); duplicate messages are silently dropped
- **Handshake replay**: Each handshake uses fresh random nonces (`client_nonce`, `server_nonce`); the transcript hash binds all messages

### Quorum Security

BFT quorum (`≥ 2/3` by default) ensures that a message is considered confirmed only when a supermajority of peers have acknowledged it. This tolerates up to `⌊(N-1)/3⌋` Byzantine peers.

---

## Performance

### Key and Signature Sizes

| Item | Size |
|------|------|
| ML-KEM-768 public key | 1,184 bytes |
| ML-KEM-768 ciphertext | ~1,088 bytes |
| X25519 public key | 32 bytes |
| X25519 ciphertext | 32 bytes |
| ML-DSA-65 public key | 1,952 bytes |
| ML-DSA-65 secret key | 4,000 bytes |
| ML-DSA-65 signature | 3,309 bytes |
| SHA-256 output (node_id, message_id, session_id) | 32 bytes |
| HMAC-SHA256 output (server_mac) | 32 bytes |

### Envelope Overhead

| Component | Size |
|-----------|------|
| Fixed fields (version, message_id, payload_type, timestamp, ttl) | ~42 bytes |
| `sender_node_id` (64-char hex string) | ~72 bytes (with bincode length prefix) |
| `sender_public_key` (ML-DSA-65 pk) | ~1,960 bytes (with bincode length prefix) |
| `signature` (ML-DSA-65 sig) | ~3,317 bytes (with bincode length prefix) |
| **Total overhead (empty payload)** | **~5,391 bytes** |
| **Total overhead (1 KB payload)** | **~6,415 bytes** |

### Expected Latency

| Operation | Typical Latency |
|-----------|----------------|
| `gossip_init` (key generation) | 50–200 ms (ML-KEM + ML-DSA keygen) |
| `gossip_encode_envelope` (sign) | 5–15 ms (ML-DSA-65 sign) |
| `gossip_verify_envelope` (verify) | 3–10 ms (ML-DSA-65 verify) |
| Full 4-message handshake (local) | 20–80 ms (2× KEM + 2× DSA ops) |
| `gossip_publish` (dedup check) | < 1 ms |

> **Note:** Latency depends heavily on the target platform. WASM execution adds ~1.5–3× overhead compared to native. ML-KEM and ML-DSA operations are the dominant cost.

### Convergence Time

For a network of `N` validators with mesh degree `D = 8` and heartbeat interval `H = 700 ms`:

```
Convergence rounds ≈ log_D(N) = log_8(N)

For N=100 validators:  log_8(100) ≈ 2.2 rounds ≈ 1.5 seconds
For N=1000 validators: log_8(1000) ≈ 3.3 rounds ≈ 2.3 seconds
```

## Where This Fits, What's Next

`witan-gossip` alone gives every gossiped message a self-authenticating, post-quantum identity that
survives relaying through any transport. It is not a transport, a broker, or a consensus engine —
see [`docs/crates.io/architecture.md`](../docs/crates.io/architecture.md) for exactly how the
crypto/protocol core and your transport layer (QUIC, TCP, WebTransport, or a broker such as NATS)
divide responsibilities, including an honest list of the risks that split introduces.

For a full comparison against libp2p gossipsub, Tendermint/CometBFT P2P, and raw NATS, see
[`docs/crates.io/comparison.md`](../docs/crates.io/comparison.md). For worked integration patterns
across native Rust, WASM hosts, and message-broker pairings, see
[`docs/crates.io/integration-guide.md`](../docs/crates.io/integration-guide.md). For extension
points — deterministic keys, standalone signature verification, multi-language embedding, bring-your-
own transport — see [`docs/crates.io/extending-customizing.md`](../docs/crates.io/extending-customizing.md).

Planned directions include finishing the Go/Python ABI bindings, a reference gRPC server, published
conformance test vectors, algorithm-agility (an alternative PQC signature scheme alongside
ML-DSA-65), reference transport adapters (QUIC, NATS/JetStream) published as separate crates, and a
third-party security audit. See [`docs/crates.io/roadmap.md`](../docs/crates.io/roadmap.md) for the
full list and the reasoning behind it.

---

## License

Licensed under either of:

- **MIT License** ([LICENSE-MIT](../LICENSE-MIT) or https://opensource.org/licenses/MIT)
- **Apache License, Version 2.0** ([LICENSE-APACHE](../LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

---

## Crate Metadata

| Field | Value |
|-------|-------|
| Crate name | `witan-gossip` |
| Library name | `witan_gossip` |
| Version | `0.1.0` |
| Edition | Rust 2021 |
| License | `Apache-2.0 OR MIT` |
| Repository | https://github.com/0x307/witan-gossip |
| WIT package | `witan:gossip@0.1.0` |
| Crate types | `cdylib` (WASM component), `rlib` (native library) |
| WASM target | `wasm32-wasip2` (component); `wasm32-wasip1` + `wasi-abi` feature (deprecated C-ABI) |