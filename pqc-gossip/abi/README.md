# witan-gossip ABI Bindings

This directory contains host-side bindings for the `witan-gossip` WASM component. Each binding loads the compiled `.wasm` binary and exposes the full gossip protocol API to the host language.

## Overview

The `witan-gossip` component is compiled to `wasm32-unknown-unknown` and uses a **wasm-bindgen-style ABI** (not the WASM Component Model). The host runtime must:

1. Load the `.wasm` binary
2. Instantiate it with a `wasmtime` (or compatible) engine
3. Allocate memory in the WASM linear memory using `__wbindgen_malloc`
4. Write input data (strings, byte slices) into WASM memory
5. Call the exported function with pointer/length pairs
6. Read the result from WASM memory via an out-pointer
7. Free WASM memory using `__wbindgen_free`

### ABI Calling Convention

All exported functions follow one of these patterns:

| Pattern | Signature | Notes |
|---------|-----------|-------|
| String in → Result\<(), E\> | `fn(ret_ptr, str_ptr, str_len)` | ret_ptr → (ok: i32, err_ptr: i32, err_len: i32) |
| String in → Result\<String, E\> | `fn(ret_ptr, str_ptr, str_len)` | ret_ptr → (ok: i32, val_ptr: i32, val_len: i32) |
| Bytes in → Result\<Bytes, E\> | `fn(ret_ptr, buf_ptr, buf_len)` | ret_ptr → (ok: i32, val_ptr: i32, val_len: i32) |
| u8 + Bytes → Result\<Bytes, E\> | `fn(ret_ptr, u8_val, buf_ptr, buf_len)` | ret_ptr → (ok: i32, val_ptr: i32, val_len: i32) |
| No args → Result\<String, E\> | `fn(ret_ptr)` | ret_ptr → (ok: i32, val_ptr: i32, val_len: i32) |

**Return value layout** (written at `ret_ptr`, 12 bytes):
- `[0..4]`  → `ok_flag: i32` — `1` = Ok, `0` = Err
- `[4..8]`  → `val_ptr: i32` — pointer to value/error string in WASM memory
- `[8..12]` → `val_len: i32` — byte length of value/error string

**Exported WASM functions:**

| Function | Description |
|----------|-------------|
| `gossip_init` | Initialize with JSON config |
| `gossip_publish` | Publish message, returns 32-byte message_id |
| `gossip_connect_peer` | Initiate PQC handshake, returns probe bytes |
| `gossip_disconnect_peer` | Remove peer session |
| `gossip_get_peers` | JSON array of connected peers |
| `gossip_get_node_identity` | JSON node identity |
| `gossip_verify_envelope` | Verify bincode envelope |
| `gossip_encode_envelope` | Encode signed envelope to bincode |
| `gossip_decode_envelope` | Decode bincode envelope to JSON |
| `gossip_get_stats` | JSON runtime statistics |
| `gossip_process_handshake_bytes` | Process incoming handshake bytes |
| `gossip_build_handshake_ack` | Build server-side handshake ACK |
| `gossip_build_finish_ack` | Build server-side finish ACK |
| `gossip_get_session` | JSON session info for a peer |
| `gossip_rotate_keys` | Rotate node keys, returns new node_id |
| `gossip_now_ms` | Current Unix timestamp in ms |
| `gossip_get_version` | Protocol version string |
| `gossip_verify_signature` | Verify standalone ML-DSA-65 signature |
| `__wbindgen_malloc` | Allocate WASM memory |
| `__wbindgen_realloc` | Reallocate WASM memory |
| `__wbindgen_free` | Free WASM memory |

---

## Bindings

### 1. Rust (`rust/`)

**When to use:** Rust services, blockchain node implementations, performance-critical hosts.

**Prerequisites:**
- Rust 1.75+
- `wasmtime` crate (see `rust/Cargo.toml`)

**Quick example:**
```rust
use witan_gossip_abi::GossipClient;

let mut client = GossipClient::from_file("target/wasm32-unknown-unknown/release/pqc_gossip.wasm")?;
client.init("{}")?;
let msg_id = client.publish(0, b"hello world")?;
println!("Published: {}", hex::encode(msg_id));
```

**Files:**
- [`rust/mod.rs`](rust/mod.rs) — Main binding implementation
- [`rust/Cargo.toml`](rust/Cargo.toml) — Crate manifest
- [`rust/example.rs`](rust/example.rs) — Usage example

---

### 2. Go (`go/`)

**When to use:** Go microservices, blockchain relay nodes, gRPC gateway servers.

**Prerequisites:**
- Go 1.21+
- `github.com/bytecodealliance/wasmtime-go/v25`

**Quick example:**
```go
import gossip "github.com/witan-gossip/witan-gossip/abi/go"

client, err := gossip.NewGossipClientFromFile("pqc_gossip.wasm")
if err != nil { log.Fatal(err) }
defer client.Close()

if err := client.Init("{}"); err != nil { log.Fatal(err) }
msgID, err := client.Publish(0, []byte("hello world"))
fmt.Printf("Published: %x\n", msgID)
```

**Files:**
- [`go/gossip.go`](go/gossip.go) — Main binding implementation
- [`go/go.mod`](go/go.mod) — Module manifest
- [`go/example_test.go`](go/example_test.go) — Usage example / integration test

---

### 3. Python (`python/`)

**When to use:** Data pipelines, monitoring tools, scripting, rapid prototyping.

**Prerequisites:**
- Python 3.11+
- `wasmtime` PyPI package (`pip install wasmtime`)

**Quick example:**
```python
from gossip import GossipClient

client = GossipClient(wasm_path="pqc_gossip.wasm")
client.init({})
msg_id = client.publish(0, b"hello world")
print(f"Published: {msg_id.hex()}")
```

**Files:**
- [`python/gossip.py`](python/gossip.py) — Main binding implementation
- [`python/requirements.txt`](python/requirements.txt) — Python dependencies
- [`python/example.py`](python/example.py) — Usage example

---

### 4. Protocol Buffers / gRPC (`proto/`)

**When to use:** Cross-language RPC, microservice meshes, language-agnostic integration.

**Prerequisites:**
- `protoc` 3.x+
- Language-specific gRPC plugin (e.g., `protoc-gen-go-grpc`, `grpcio-tools`)

**Quick example (Go gRPC client):**
```go
conn, _ := grpc.Dial("localhost:50051", grpc.WithInsecure())
client := gossipv1.NewGossipServiceClient(conn)
resp, _ := client.Init(ctx, &gossipv1.InitRequest{ConfigJson: "{}"})
```

**Files:**
- [`proto/gossip.proto`](proto/gossip.proto) — Complete protobuf v3 definition

**Generate Go stubs:**
```bash
protoc --go_out=. --go-grpc_out=. proto/gossip.proto
```

**Generate Python stubs:**
```bash
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. proto/gossip.proto
```

---

## Error Codes

All bindings surface the same error taxonomy from [`GossipError`](../src/error.rs):

| Code | Meaning |
|------|---------|
| `NOT_INITIALIZED` | `gossip_init` not yet called |
| `ALREADY_INITIALIZED` | `gossip_init` called more than once |
| `CONFIG_ERROR` | Invalid JSON config or field value |
| `IDENTITY_ERROR` | Key generation or seed parsing failed |
| `HANDSHAKE_ERROR` | PQC handshake protocol violation |
| `SESSION_NOT_FOUND` | No active session for peer address |
| `ENVELOPE_ERROR` | Envelope encode/decode/validation error |
| `SIGNATURE_INVALID` | ML-DSA-65 signature verification failed |
| `REPLAY_DETECTED` | Message timestamp outside ±30s window |
| `TTL_EXPIRED` | Envelope hop count reached zero |
| `PEER_NOT_FOUND` | Peer address not in active session store |
| `QUORUM_NOT_REACHED` | BFT quorum threshold not met |
| `SERIALIZATION_ERROR` | bincode or serde_json error |
| `CRYPTO_ERROR` | PQC cryptographic operation failed |
| `INVALID_INPUT` | Invalid function argument |

---

## Payload Types

| Value | Name | Description |
|-------|------|-------------|
| `0` | `Transaction` | Blockchain transaction |
| `1` | `BlockProposal` | Block proposal from validator |
| `2` | `FinalityVote` | Finality vote from validator |
| `3` | `StateSync` | State synchronization data |
| `4` | `PeerDiscovery` | Peer discovery advertisement |

---

## Building the WASM Binary

```bash
cd pqc-gossip
cargo build --target wasm32-unknown-unknown --release
# Output: target/wasm32-unknown-unknown/release/pqc_gossip.wasm
```

---

## Security Notes

- The WASM component holds **private keys** in its linear memory. Treat the WASM instance as a security boundary.
- Each WASM instance is **single-threaded** and maintains a global singleton state via `OnceLock`.
- Do **not** share a single WASM instance across threads without external synchronization.
- Key rotation via `gossip_rotate_keys` invalidates all existing sessions.
