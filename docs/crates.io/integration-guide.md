# Integration Guide

This guide walks through the practical patterns for embedding `witan-gossip` in a host application.
For the full function-by-function API reference, wire format, and build instructions, see the
[crate README](../../pqc-gossip/README.md). For *why* the integration boundary looks the way it
does, see [`architecture.md`](architecture.md).

---

## 1. Choose your embedding mode

| Mode | When to use it | How |
|---|---|---|
| **Native Rust `rlib`** | Your host is Rust and you don't need WASM sandboxing | `witan-gossip = { version = "0.1", default-features = false }` as a normal dependency |
| **WASM Component via `wasmtime`** | You want the sandboxing/portability guarantees, or a non-Rust host | Build with `cargo build --target wasm32-wasip2 --release`, load with `wasmtime::component` |
| **Go / Python host** | Your host isn't Rust | Generate bindings from [the WIT interface](../../pqc-gossip/wit/gossip-protocol.wit) with `wit-bindgen-go` or `componentize-py` |
| **gRPC / Protobuf proxy** | You want a language-agnostic network boundary instead of embedding WASM directly | Generate a service contract from the WIT interface and front the engine with a small gRPC server |

> **Note on the `rlib` row:** `default-features = false` turns off the `component` feature. You want
> that when embedding this crate as a library inside your *own* component — otherwise its exported
> interface is merged into your component's world. It makes no difference for a native host.

---

## 2. Native Rust integration (fastest path)

```toml
[dependencies]
witan-gossip = "0.1"
```

```rust
use witan_gossip::{gossip_init, gossip_publish, gossip_encode_envelope, gossip_verify_envelope};
use witan_gossip::types::PayloadType;

gossip_init(r#"{"mesh_n": 6, "default_ttl": 5}"#)?;
let msg_id = gossip_publish(PayloadType::Transaction as u8, b"tx-bytes")?;
let envelope_bytes = gossip_encode_envelope(PayloadType::Transaction as u8, b"tx-bytes")?;
// send envelope_bytes over whatever transport you have
```

This is the right choice for test harnesses, sidecars, or any Rust service that doesn't need the
WASM sandbox boundary.

---

## 3. WASM Component host (Wasmtime, Rust)

```rust
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::WasiCtxBuilder;

let mut config = Config::new();
config.wasm_component_model(true);
let engine = Engine::new(&config)?;

let component = Component::from_file(&engine, "witan_gossip.wasm")?;
let wasi = WasiCtxBuilder::new().build();
let mut store = Store::new(&engine, wasi);

let mut linker = Linker::new(&engine);
wasmtime_wasi::add_to_linker_sync(&mut linker)?;
let instance = linker.instantiate(&mut store, &component)?;

let gossip_init = instance.get_typed_func::<(String,), (Result<(), _>,)>(&mut store, "gossip-init")?;
gossip_init.call(&mut store, (r#"{}"#.to_string(),))?;
```

This is the right choice when you want the security/portability guarantees of the Component Model,
or when your host is not Rust and you're driving the component through a generic `wasmtime` runtime.

The [`wasmtime-test`](../../wasmtime-test/) harness in this repository is a working multi-node example
of exactly this pattern — it drives 3 in-process instances of the compiled component through a full
handshake and gossip exchange, which is a good template for your own integration tests.

---

## 4. Non-Rust hosts (Go, Python)

The component is a standard WASM Component, so Go and Python hosts generate their bindings from the
same [`wit/gossip-protocol.wit`](../../pqc-gossip/wit/gossip-protocol.wit) the Rust guest is
generated from:

```bash
# Go
wit-bindgen-go generate --world gossip-world pqc-gossip/wit

# Python
componentize-py --wit-path pqc-gossip/wit --world gossip-world bindings .
```

Drive the resulting bindings with your language's `wasmtime` runtime the same way the Rust host in
§3 does.

**We do not ship hand-written bindings for these languages, deliberately.** An earlier revision of
this repository did, and they had drifted from the interface they wrapped — wrong symbol names,
wrong target, wrong allocator — while still reading like working code. A binding that has silently
drifted from a *cryptographic* interface is worse than no binding, so the interface is published as
the contract and generation is left to the tools that stay in sync with it. First-party generated
examples are on the roadmap.

---

## 5. Pairing with a transport

`witan-gossip` never touches the network. You drive it with three kinds of calls:

1. **Handshake bytes** — `gossip_connect_peer` / `gossip_process_handshake_bytes` /
   `gossip_build_handshake_ack` / `gossip_build_finish_ack` — produce and consume the 4-message PQC
   handshake.
2. **Envelope bytes** — `gossip_encode_envelope` (to send) / `gossip_verify_envelope` (on receipt).
3. **Bookkeeping** — `gossip_get_peers`, `gossip_get_stats`, `gossip_get_session`.

### Pattern A — raw QUIC/TCP loop

```rust
// Sending
let envelope = gossip_encode_envelope(PayloadType::Transaction as u8, payload)?;
for peer in mesh_peers {
    transport.send(peer, &envelope);
}

// Receiving
let bytes = transport.recv(peer_addr);
if gossip_verify_envelope(&bytes)? {
    let json = gossip_decode_envelope(&bytes)?;
    // hand off to your application
}
```

### Pattern B — pairing with NATS (or `erend-nats`)

```rust
// Publisher side
let envelope = gossip_encode_envelope(payload_type, payload)?;
nats_client.publish(subject_for(payload_type), envelope).await?;

// Subscriber side
let msg = subscription.next().await?;
if gossip_verify_envelope(&msg.payload)? {
    let json = gossip_decode_envelope(&msg.payload)?;
    // hand off to your application
}
```

NATS (or any pub/sub broker) handles the "who gets this message" fan-out question. `witan-gossip`
handles the "can I trust this message" question. Neither call site changes if you later swap the
broker for raw QUIC, or vice versa — see [`architecture.md`](architecture.md) for why that's the
point of the boundary.

### Pattern C — in-process test harness

For CI, drive multiple component instances inside a single process (as `wasmtime-test` does) and
exchange the bytes directly, with no real network at all. This lets you test the full handshake and
envelope-verification logic deterministically, without flakiness from real sockets.

---

## 6. Handling the handshake end-to-end

```
Client                                              Server
  │──[1] gossip_connect_peer() → probe bytes ────────►│
  │                                                    │  gossip_process_handshake_bytes(probe)
  │◄──[2] ack bytes ───────────────────────────────────│  (or gossip_build_handshake_ack directly)
  │  gossip_process_handshake_bytes(ack) → finish bytes│
  │──[3] finish bytes ────────────────────────────────►│
  │                                                    │  gossip_build_finish_ack(finish)
  │◄──[4] finish_ack bytes ─────────────────────────────│
  │  gossip_process_handshake_bytes(finish_ack) → None │
  │═══════════════ SESSION ESTABLISHED ════════════════│
```

`gossip_process_handshake_bytes` inspects the magic-byte prefix of incoming bytes and dispatches to
the right internal handler automatically — your host doesn't need to track handshake phase itself,
just keep calling it with whatever bytes arrive on a given peer's connection until it returns `None`.

---

## 7. Configuration checklist

Before going to production, review these `gossip_init` config fields against your deployment:

| Field | Consideration |
|---|---|
| `mesh_n` / `mesh_n_low` / `mesh_n_high` | Match your expected validator/peer count and desired redundancy |
| `quorum_fraction` | Usually `0.67` for classic BFT; adjust to your chain's finality rule |
| `default_ttl` | Must be large enough to reach all peers in `O(log_mesh_n(N))` hops |
| `replay_window_ms` | Tighter windows reduce replay risk but require tighter clock sync across your mesh |
| `dedup_cache_secs` | Should exceed your expected worst-case multi-path delivery skew |
| `max_message_bytes` | Set to your largest expected payload (e.g., block bodies vs. individual transactions) |
| `kem_seed_hex` / `sig_seed_hex` | Supply these for deterministic validator identity across restarts; omit for ephemeral/test nodes |

---

## 8. Error handling

Every fallible function returns `GossipError`. Treat these as first-class signals, not just log
lines — several of them (`ReplayDetected`, `SignatureInvalid`, `TtlExpired`) are exactly the
conditions the protocol is designed to catch:

```rust
match gossip_verify_envelope(&bytes) {
    Ok(true) => { /* trust it */ }
    Ok(false) => { /* malformed but not an error variant — treat as untrusted */ }
    Err(GossipError::ReplayDetected) => { /* drop, maybe log as a metric */ }
    Err(GossipError::SignatureInvalid) => { /* drop, consider peer scoring */ }
    Err(e) => { /* other error — see the full taxonomy in pqc-gossip/src/error.rs */ }
}
```

---

## 9. Testing your integration

- Reuse the [`wasmtime-test`](../../wasmtime-test/) harness pattern as a starting point for a
  multi-node, in-process integration test.
- The crate's own [integration test suite](../../pqc-gossip/tests/integration_tests.rs) is a good
  reference for exercising handshake, envelope, dedup, and quorum logic in isolation.
- If you're pairing with a real transport (QUIC/TCP/NATS), write a small "loopback" test first:
  one process, two `witan-gossip` instances, bytes copied directly between them with no network —
  this isolates transport bugs from protocol bugs.
