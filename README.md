# Witan

A post-quantum cryptography (PQC) gossip protocol engine, compiled as a
[WASM Component Model](https://component-model.bytecodealliance.org/) component. It provides
epidemic broadcast messaging with quantum-resistant cryptographic guarantees for
validator-to-validator communication in a blockchain validator mesh.

**`witan` is self-contained and useful on its own.** It has no required companions: it takes
bytes in and gives bytes out, so any host that can move bytes — QUIC, TCP, WebTransport, a message
broker, or your own transport — can drive it. Everything below is optional context, not a dependency
list.

### Where it fits in a full validator node

We're building it as one of three cooperating WASM runtimes, each an independent component with a
clear ownership boundary. You can adopt this one without the other two.

| Runtime | Role | Status |
|---|---|---|
| **Blockchain Runtime** | Owns consensus, block production, and state machine logic. Calls into the Gossip Runtime to publish messages and receive validated gossip. Has no direct network access. | Not yet published |
| **Gossip Protocol Runtime** (this repo) | Owns all PQC cryptographic operations and gossip protocol logic. Validates incoming bytes and delivers verified messages to the host. | `witan` — this crate |
| **Erend-NATS Runtime** | Wraps `async-nats` client functionality. Owns subject routing, JetStream consumer management, and NATS cluster connectivity. | Not yet published |

The split is the point: transport concerns and cryptographic concerns evolve on different timelines,
so a transport change never forces a re-review of the crypto core. See
[`docs/crates.io/architecture.md`](docs/crates.io/architecture.md) for the full rationale, including
an honest account of the risks the split introduces.

## What's in this repo

- [`witan/`](witan/) — the `witan` crate: a WASM component implementing the PQC
  gossip protocol (ML-KEM-768 + X25519 hybrid handshake, ML-DSA-65 signatures, envelope
  sign/verify, deduplication, BFT quorum tracking, replay protection, TTL hop-count management).
  This is the crate published to crates.io.
- [`wasmtime-test/`](wasmtime-test/) — a multi-instance `wasmtime` test harness that runs a
  3-node gossip mesh entirely in-process, driving the compiled WASM component the same way a
  host blockchain runtime would.
- [`docs/crates.io/`](docs/crates.io/) — the public documentation set: an extended README, the
  architecture/layering rationale (`witan` vs. transport layers like QUIC/TCP/NATS), an
  integration guide, extension points, a competitive comparison, and the roadmap.


## Key responsibilities of the Gossip Protocol Runtime

- PQC handshake (X25519 + ML-KEM-768 + ML-DSA-65)
- Envelope signing and verification
- Deduplication (SHA-256 message IDs, 60s TTL cache)
- Quorum tracking (≥2/3 BFT threshold)
- Replay protection (±30s window)
- TTL hop count management

See [`witan/README.md`](witan/README.md) for the full crate documentation, WIT
interface, build instructions, and API reference.

## What runs today vs. what is designed

**Runs today, and is exercised in CI on every push:**

- The native Rust library, with 10 integration tests covering identity generation and
  derivation from seeds, ML-DSA-65 sign/verify, envelope round-trip, replay detection, the
  dedup cache, the quorum tracker, the full 4-message handshake, and config validation.
- The `wasm32-wasip2` build, emitting a WASM Component that exports
  `witan:gossip/gossip-protocol@0.1.0`. CI asserts the export exists on the built artifact.
- A 3-node in-process `wasmtime` mesh driving the component through mutual handshakes,
  envelope signing, cross-node verification, and disconnect.
- `cargo component build` as an equivalent path via `wasm32-wasip1` plus an adapter.
- The deprecated `wasi-abi` C-ABI surface, built both in isolation and alongside the
  component export.
- The published crate itself: CI packages it and rebuilds those exact bytes for
  `wasm32-wasip2`, because a native-only `--dry-run` cannot see code behind a `cfg`.

**Designed, or deliberately left to the host:**

- **Fan-out and mesh membership are the host's job.** This crate tracks sessions it is told
  about and exposes `mesh_n` / `mesh_n_low` / `mesh_n_high` as guidance; deciding which peers a
  message goes to, and actually sending it, happens outside the component.
- **Quorum tracking counts acknowledgements you feed it.** It does not collect them.
- **Mesh graft/prune during `heartbeat()` is implemented but not covered by a multi-node test.**
  The 3-node harness exercises handshake and messaging, not mesh convergence under churn.
- **TTL is enforced on verify, not decremented on forward** — forwarding is host-side, so
  decrementing before rebroadcast is the host's responsibility.
- **No third-party security audit.** See [`SECURITY.md`](SECURITY.md) and
  [`STABILITY.md`](STABILITY.md).
- **Go and Python bindings are generatable but not shipped** as first-party worked examples,
  and no `.proto` ships for the gRPC path. See
  [`docs/crates.io/roadmap.md`](docs/crates.io/roadmap.md).
- **The two sibling runtimes** in the table above are not published.

## Building

```bash
# Build the native rlib (tests, tooling)
cargo build -p witan

# Build the WASM component
rustup target add wasm32-wasip2
cargo build -p witan --target wasm32-wasip2 --release

# Run the in-process 3-node integration harness against the built component
cargo run -p wasmtime-test -- target/wasm32-wasip2/release/witan.wasm
```

`wasm32-wasip2` emits a WASM Component directly — no post-processing step.
Inspect the artifact and its interface with:

```bash
wasm-tools component wit target/wasm32-wasip2/release/witan.wasm
```

`cargo component build -p witan --release` also works and produces an
equivalent component via `wasm32-wasip1` plus an adapter. Both paths are covered
in CI.

### Consuming this crate as a library

The component export is emitted by an `export!` macro, and a dependency's
exports are merged into the root crate's world. If you depend on `witan`
from your own wasm component, disable the default `component` feature so its
interface doesn't become part of *your* component's public surface:

```toml
witan = { version = "0.1", default-features = false }
```

The full Rust API stays available either way. See
[`witan/README.md`](witan/README.md#depending-on-this-crate-from-your-own-component).

### Deprecated: legacy C-ABI

Before the component export existed, this crate exposed a hand-rolled ptr/len
C-ABI (`gossip_*_wasi`) for `wasm32-wasip1` core-module hosts. It survives behind
an off-by-default feature for consumers who already integrated against it, and is
scheduled for removal in a future release:

```bash
cargo build -p witan --target wasm32-wasip1 --release --features wasi-abi
```

New integrations should use the component interface, which needs no feature flag
and no manual memory management.

`wasm32-unknown-unknown` is **not** supported: it has no WASI wall clock, so the
crate deliberately fails to build there rather than compiling and then panicking
at runtime.

## Testing

```bash
cargo test -p witan
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
