# Witan-Gossip

A post-quantum cryptography (PQC) gossip protocol engine, compiled as a
[WASM Component Model](https://component-model.bytecodealliance.org/) component. It provides
epidemic broadcast messaging with quantum-resistant cryptographic guarantees for
validator-to-validator communication in a blockchain validator mesh.

**`witan-gossip` is self-contained and useful on its own.** It has no required companions: it takes
bytes in and gives bytes out, so any host that can move bytes — QUIC, TCP, WebTransport, a message
broker, or your own transport — can drive it. Everything below is optional context, not a dependency
list.

### Where it fits in a full validator node

We're building it as one of three cooperating WASM runtimes, each an independent component with a
clear ownership boundary. You can adopt this one without the other two.

| Runtime | Role | Status |
|---|---|---|
| **Blockchain Runtime** | Owns consensus, block production, and state machine logic. Calls into the Gossip Runtime to publish messages and receive validated gossip. Has no direct network access. | Not yet published |
| **Gossip Protocol Runtime** (this repo) | Owns all PQC cryptographic operations and gossip protocol logic. Validates incoming bytes and delivers verified messages to the host. | `witan-gossip` — this crate |
| **Erend-NATS Runtime** | Wraps `async-nats` client functionality. Owns subject routing, JetStream consumer management, and NATS cluster connectivity. | Not yet published |

The split is the point: transport concerns and cryptographic concerns evolve on different timelines,
so a transport change never forces a re-review of the crypto core. See
[`docs/crates.io/architecture.md`](docs/crates.io/architecture.md) for the full rationale, including
an honest account of the risks the split introduces.

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
rustup target add wasm32-wasip2
cargo build -p witan-gossip --target wasm32-wasip2 --release

# Run the in-process 3-node integration harness against the built component
cargo run -p wasmtime-test -- target/wasm32-wasip2/release/witan_gossip.wasm
```

`wasm32-wasip2` emits a WASM Component directly — no post-processing step.
Inspect the artifact and its interface with:

```bash
wasm-tools component wit target/wasm32-wasip2/release/witan_gossip.wasm
```

`cargo component build -p witan-gossip --release` also works and produces an
equivalent component via `wasm32-wasip1` plus an adapter. Both paths are covered
in CI.

### Consuming this crate as a library

The component export is emitted by an `export!` macro, and a dependency's
exports are merged into the root crate's world. If you depend on `witan-gossip`
from your own wasm component, disable the default `component` feature so its
interface doesn't become part of *your* component's public surface:

```toml
witan-gossip = { version = "0.1", default-features = false }
```

The full Rust API stays available either way. See
[`pqc-gossip/README.md`](pqc-gossip/README.md#depending-on-this-crate-from-your-own-component).

### Deprecated: legacy C-ABI

Before the component export existed, this crate exposed a hand-rolled ptr/len
C-ABI (`gossip_*_wasi`) for `wasm32-wasip1` core-module hosts. It survives behind
an off-by-default feature for consumers who already integrated against it, and is
scheduled for removal in a future release:

```bash
cargo build -p witan-gossip --target wasm32-wasip1 --release --features wasi-abi
```

New integrations should use the component interface, which needs no feature flag
and no manual memory management.

`wasm32-unknown-unknown` is **not** supported: it has no WASI wall clock, so the
crate deliberately fails to build there rather than compiling and then panicking
at runtime.

## Testing

```bash
cargo test -p witan-gossip
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
