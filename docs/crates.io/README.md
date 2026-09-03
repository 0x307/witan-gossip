# witan-gossip

**The post-quantum-native gossip protocol engine for blockchains and mesh networks.**

[![Crates.io](https://img.shields.io/crates/v/witan-gossip.svg)](https://crates.io/crates/witan-gossip)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](../../pqc-gossip/README.md#license)
[![WASM Component](https://img.shields.io/badge/target-wasm32--unknown--unknown-orange.svg)](https://webassembly.org/)
[![FIPS 203](https://img.shields.io/badge/FIPS-203%20ML--KEM--768-green.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![FIPS 204](https://img.shields.io/badge/FIPS-204%20ML--DSA--65-green.svg)](https://csrc.nist.gov/pubs/fips/204/final)

> This document is the extended, narrative companion to the crate's published
> [`README`](../../pqc-gossip/README.md). Read this first for the *why*; read the crate README for the
> *exact API*.

---

## The one-sentence pitch

`witan-gossip` is a small, auditable, **WASM Component Model** engine that gives every message in your
gossip mesh its own **quantum-resistant cryptographic identity** — ML-KEM-768 + X25519 hybrid key
exchange (FIPS 203) and ML-DSA-65 signatures (FIPS 204) — so that authenticity and freshness survive
*no matter how many hops, relays, or brokers the message passes through*, while leaving transport
(QUIC, TCP, WebTransport, NATS, or anything else) entirely to the host.

---

## Why this is different from everything else out there

Every gossip stack in production today — libp2p gossipsub, Tendermint/CometBFT P2P, raw NATS
fan-out — secures the **pipe**, not the **message**. TLS (classical, and even the emerging
hybrid-PQC variants) protects data *in transit between two directly connected peers*. The instant a
message is relayed, rebroadcast, or forwarded through a message broker, that protection is gone: the
next hop is a new TLS session trusting whatever the previous hop handed it.

`witan-gossip` signs the **envelope itself**, not the pipe:

```
GossipEnvelope {
    message_id,          // SHA-256(payload_type || payload)
    sender_node_id,       // SHA-256(kem_pk || sig_pk)
    sender_public_key,    // ML-DSA-65 public key, carried with the message
    payload_type, payload,
    signature,             // ML-DSA-65 signature over message_id || payload_type || payload
    timestamp_unix_ms, ttl,
}
```

Because the signature and the signer's public key travel *inside* the message, **any node, at any
hop, through any transport — including an untrusted relay, a public NATS backbone, or a plain TCP
proxy — can independently verify who sent a message and when**, without re-establishing trust at
every hop. That is the property that matters for blockchain gossip, and it is the property almost
nothing else in the ecosystem gives you for free.

Combine that with:

- **Post-quantum by default, not bolted on.** ML-KEM-768 + X25519 hybrid KEM and ML-DSA-65 are the
  baseline, not an opt-in mode. There is no classical-only code path to accidentally ship.
- **WASM Component Model portability.** Compile once to `wasm32-wasip2`, embed the same
  binary in a Rust, Go, Python, or Node.js host via `wasmtime`. One auditable crypto core, any
  language, no re-implementation risk.
- **A deliberately small, auditable core.** No sockets, no async runtime, no libp2p, no TLS stack
  inside the component. Fewer moving parts in the security-critical layer means a smaller attack
  surface and a faster, cheaper audit.
- **BFT quorum, dedup, replay protection, and TTL hop-limiting** included out of the box — the
  primitives every gossip mesh needs, in one crate, instead of five.
- **Free and permissively licensed** (Apache-2.0 OR MIT). No token, no vendor lock-in, no
  "enterprise tier" gate on the cryptography.

---

## What `witan-gossip` is — and is not

| It IS | It is NOT |
|---|---|
| A PQC handshake + envelope sign/verify engine | A transport (no sockets, no QUIC/TCP/UDP code) |
| A dedup / replay-protection / TTL state machine | A consensus engine (no block production, no voting rules) |
| A BFT quorum *tracker* (counts acks toward a threshold) | A finality *decider* (your chain defines what finality means) |
| A WASM Component with a versioned WIT interface | A message broker (no pub/sub fan-out, no persistence) |
| Host-language agnostic (Rust / Go / Python / gRPC) | Blockchain-specific (no hardcoded chain assumptions) |

---

## The layered model, in one picture

```
┌────────────────────────────────────────────────────────────────────┐
│                     YOUR HOST PROCESS                              │
│                                                                    │
│   Transport you choose: QUIC · TCP · WebTransport · NATS/JetStream │
│   (or erend-nats, or anything else that moves bytes)               │
│        recv bytes ───────────────────────────► send bytes          │
│                     │                           ▲                  │
│                     ▼  WIT / ABI calls          │ response bytes   │
│   ┌──────────────────────────────────────────────────────────┐     │
│   │            witan-gossip (WASM component)                 │     │
│   │   PQC handshake · envelope sign/verify · dedup ·         │     │
│   │   quorum tracking · replay protection · TTL              │     │
│   └──────────────────────────────────────────────────────────┘     │
└────────────────────────────────────────────────────────────────────┘
```

The host owns **delivery**. `witan-gossip` owns **trust**. Neither layer needs to know how the other
works internally — that boundary is the whole point. See
[`architecture.md`](architecture.md) for the full rationale, and the honest list of challenges that
this abstraction introduces.

---

## `witan-gossip` alone vs. a transport/messaging layer (e.g. NATS / erend-nats)

| Capability | `witan-gossip` provides | A transport/messaging layer provides |
|---|---|---|
| Node identity (KEM + SIG keypairs) | ✅ | — |
| Mutual PQC handshake & session establishment | ✅ | — |
| Message signing & verification (ML-DSA-65) | ✅ | — |
| Message deduplication (seen-before cache) | ✅ | ⚠️ complementary (broker dedup ≠ crypto dedup) |
| Replay-window / freshness enforcement | ✅ | — |
| TTL / hop-count enforcement | ✅ | — |
| BFT quorum (ack counting) | ✅ | — |
| Physical connectivity, socket lifecycle | — | ✅ |
| Peer fan-out / pub-sub distribution | — | ✅ |
| Congestion control, retransmission, NAT traversal | — | ✅ |
| Durable persistence / replay of missed messages | — | ✅ (e.g. JetStream-style streams) |
| Subject/topic-based filtering & clustering | — | ✅ |

Neither layer is a substitute for the other. `witan-gossip` gives every message a cryptographic
identity that outlives any single hop; the transport gets the bytes there. Pair them and you get
epidemic broadcast with end-to-end, quantum-resistant authenticity — something neither layer
provides alone.

---

## Quick start

```rust
use witan_gossip::{gossip_init, gossip_encode_envelope, gossip_verify_envelope, types::PayloadType};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    gossip_init("{}")?; // defaults: mesh_n=8, ttl=8, quorum_fraction=0.67, ...

    let envelope = gossip_encode_envelope(PayloadType::Transaction as u8, b"my_tx_bytes")?;
    // hand `envelope` to whatever transport you're using — QUIC, TCP, NATS, anything.

    assert!(gossip_verify_envelope(&envelope)?);
    Ok(())
}
```

For the complete API reference, WIT interface, wire format, handshake sequence diagrams, and build
instructions, see the [crate README](../../pqc-gossip/README.md).

---

## Documentation map

| Document | What's in it |
|---|---|
| [`README.md`](README.md) (this file) | The pitch, the layering model, quick start |
| [`architecture.md`](architecture.md) | Why the layers are split this way, what each side owns, honest risks |
| [`integration-guide.md`](integration-guide.md) | Worked integration patterns: native Rust, WASM host, NATS pairing, test harness |
| [`extending-customizing.md`](extending-customizing.md) | Extension points that exist today, and how to build on them |
| [`comparison.md`](comparison.md) | How `witan-gossip` stacks up against libp2p, Tendermint P2P, and raw NATS |
| [`roadmap.md`](roadmap.md) | What's coming next |
| [`about.md`](about.md) | Where the names "Witan" and "Erend" come from |

---

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or
[MIT license](../../LICENSE-MIT) at your option.
