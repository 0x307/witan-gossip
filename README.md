# Witan-Gossip

A white-label, post-quantum cryptography (PQC) gossip protocol runtime, compiled as a
[WASM Component Model](https://component-model.bytecodealliance.org/) component. It provides
epidemic broadcast messaging with quantum-resistant cryptographic guarantees for
validator-to-validator communication in a blockchain validator mesh.

This repository contains the **Gossip Protocol Runtime** — one of three cooperating WASM
runtimes in a larger validator-node architecture:

| Runtime | Role | Repository |
|---|---|---|
| **Blockchain Runtime** | Owns consensus, block production, and state machine logic. Calls into the Gossip Runtime to publish messages and receive validated gossip. Has no direct network access. | (separate repo) |
| **Gossip Protocol Runtime** (this repo) | Owns all PQC cryptographic operations and gossip protocol logic. Receives raw bytes from the NATS runtime, validates them, and delivers verified messages to the Blockchain Runtime. | `witan-gossip` |
| **Erend-NATS Runtime** | Wraps `async-nats` client functionality. Owns subject routing, JetStream consumer management, and NATS cluster connectivity. | (separate repo) |

## What's in this repo

- [`pqc-gossip/`](pqc-gossip/) — the `witan-gossip` crate: a WASM component implementing the PQC
  gossip protocol (ML-KEM-768 + X25519 hybrid handshake, ML-DSA-65 signatures, envelope
  sign/verify, deduplication, BFT quorum tracking, replay protection, TTL hop-count management).
  This is the crate published to crates.io.
- [`wasmtime-test/`](wasmtime-test/) — a multi-instance `wasmtime` test harness that runs a
  3-node gossip mesh entirely in-process, driving the compiled WASM component the same way a
  host blockchain runtime would.
- [`docs/crates.io/`](docs/crates.io/) — the public documentation set: an extended README, the
  architecture/layering rationale (`witan-gossip` vs. transport layers like QUIC/TCP/NATS), an
  integration guide, extension points, a competitive comparison, and the roadmap.


## Key responsibilities of the Gossip Protocol Runtime

- PQC handshake (X25519 + ML-KEM-768 + ML-DSA-65)
- Envelope signing and verification
- Deduplication (SHA-256 message IDs, 60s TTL cache)
- Quorum tracking (≥2/3 BFT threshold)
- Replay protection (±30s window)
- TTL hop count management

See [`pqc-gossip/README.md`](pqc-gossip/README.md) for the full crate documentation, WIT
interface, build instructions, and API reference.

## Building

```bash
# Build the native rlib (tests, tooling)
cargo build -p witan-gossip

# Build the WASM component
rustup target add wasm32-wasip1
cargo build -p witan-gossip --target wasm32-wasip1 --release

# Run the in-process 3-node integration harness against the built component
cargo run -p wasmtime-test -- target/wasm32-wasip1/release/witan_gossip.wasm
```

## Testing

```bash
cargo test -p witan-gossip
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
