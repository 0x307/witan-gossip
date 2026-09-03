# Extending & Customizing `witan`

`witan` is deliberately a small core. Rather than growing a large plugin-trait surface inside
the crypto-critical WASM component, extensibility is designed around **stable, versioned interfaces
at the edges** — the WIT world, the config schema, and the wire format — so you can build richer
behavior in the host without ever needing to fork or patch the core.

This document walks through every extension point that exists today, and the intended patterns for
building on top of them.

---

## 1. Configuration-driven tuning (no recompilation needed)

Everything in the table below is a runtime knob passed as JSON to `gossip_init`, not a compile-time
feature. This is the first and easiest customization axis:

```json
{
  "mesh_n": 12,
  "mesh_n_low": 6,
  "mesh_n_high": 18,
  "heartbeat_ms": 500,
  "max_message_bytes": 4194304,
  "dedup_cache_secs": 120,
  "quorum_fraction": 0.75,
  "replay_window_ms": 15000,
  "default_ttl": 10
}
```

Different validator sets, different network sizes, and different latency budgets can all be
accommodated without a single line of Rust changing.

---

## 2. Bring your own key management

Rather than always generating ephemeral keys, supply `kem_seed_hex` / `sig_seed_hex` in the init
config to derive a deterministic identity from a seed you control:

```json
{
  "kem_seed_hex": "…192 hex chars, from your KMS/HSM…",
  "sig_seed_hex": "…64 hex chars, from your KMS/HSM…",
  "key_epoch": "validator-epoch-7"
}
```

This is the integration point for teams that want their PQC seed material sourced from a hardware
security module, a threshold key-generation ceremony, or an existing key-management pipeline,
instead of relying on the component's own RNG. `gossip_rotate_keys()` gives you a rotation hook you
can call on your own schedule (e.g., per epoch), and `key_epoch` is carried in the public identity
JSON purely as an informational label for your own bookkeeping.

---

## 3. Standalone signature verification

`gossip_verify_signature(public_key, message, signature, context)` verifies an ML-DSA-65 signature
outside the gossip envelope flow entirely. Use this to extend PQC authentication into your own
protocol messages — for example, verifying a node's identity claim in a custom discovery message,
or checking a signature on data that never goes through `GossipEnvelope` at all. It's the same
verification primitive the gossip engine uses internally, exposed as a building block.

---

## 4. `PayloadType` — carrying your own data

The `PayloadType` enum (`Transaction`, `BlockProposal`, `FinalityVote`, `StateSync`,
`PeerDiscovery`) is a routing/priority hint, not a schema constraint. The `payload: Vec<u8>` field
is opaque to `witan` — put whatever your application needs inside it (protobuf, bincode,
JSON, a custom binary format). Most integrations get everything they need from the five built-in
variants:

- Use `StateSync` for large, infrequent blobs.
- Use `PeerDiscovery` to carry your own `PeerInfo`-shaped or custom discovery payloads.
- Use `Transaction` / `BlockProposal` / `FinalityVote` for anything that maps naturally to those
  semantics in your chain.

If your use case genuinely needs more discriminants than the five provided, that's tracked as a
possible WIT interface addition — see [`roadmap.md`](roadmap.md). Because the WIT world is
versioned (`witan:gossip@0.1.0`), additions are designed to be additive and backward compatible
rather than breaking changes.

---

## 5. Multi-language embedding as an extension point

Because the engine is exposed as both a native Rust `rlib` and a WASM Component, you can build
tooling around it in whatever language your organization standardizes on, without waiting for us to
ship a first-party binding:

- **Rust** — direct crate dependency (`rlib`), zero indirection.
- **Any Component Model host** — instantiate the `.wasm` via `wasmtime` (or another
  Component-Model-compatible runtime) and call the WIT functions directly.
- **Go / Python** — generate bindings from
  [the WIT interface](../../witan/wit/gossip-protocol.wit) with `wit-bindgen-go` or
  `componentize-py`. Generating from the interface is the point: hand-written bindings drift from
  the API they wrap, and a binding that has drifted from a cryptographic interface is worse than no
  binding at all.
- **gRPC** — no first-party `.proto` ships today. The WIT interface is the source of truth, so
  generate the service contract from it rather than maintaining a parallel hand-written schema, then
  front the engine with a small server and any gRPC client language becomes a valid host.

This means you can, for example, write a small sidecar in your language of choice that embeds the
component and exposes it over a local socket or gRPC to the rest of your stack — a common pattern
for teams that don't want a WASM runtime dependency inside their main service.

---

## 6. Bring your own transport (the big one)

As covered in [`architecture.md`](architecture.md), `witan` never touches the network. This
is itself the primary extension point: you are free to pair the engine with:

- Raw QUIC or TCP sockets you manage yourself.
- WebTransport, for browser-based clients.
- A message broker such as NATS/JetStream (see the companion `erend-nats`-style pattern in
  [`integration-guide.md`](integration-guide.md#5-pairing-with-a-transport)).
- Any application-specific overlay network you already operate.

Because the only contract is "bytes in, bytes out," swapping transports is a host-side change that
never touches the cryptographic core, and never requires re-validating the PQC logic.

---

## 7. Building a plugin layer on top, on the host side

Many teams integrating a gossip engine into a larger blockchain runtime find it useful to define
their *own* small trait/interface layer in their host code — e.g., something that maps their
transaction batch format to `gossip_publish` calls, or routes `gossip_get_stats()` output into their
existing metrics pipeline. `witan` intentionally stays out of prescribing that shape: it's
your host's composition root, and it should reflect your chain's types and conventions, not ours.
The stable surface you compose against is the WIT/ABI function list — everything above it is yours
to design.

---

## 8. What is intentionally *not* customizable

A few things are fixed by design, because they are safety properties, not limitations:

- **Domain-separation context strings** (`SIG_CTX_MESSAGE`, `SIG_CTX_HANDSHAKE`, `SIG_CTX_NODE_ID`)
  are protocol constants. They exist specifically to prevent a signature produced for one purpose
  (e.g., a handshake transcript) from being replayed as if it were valid for another purpose (e.g.,
  a message envelope). Making these configurable would reopen exactly the class of cross-protocol
  signature-reuse vulnerability they're designed to close.
- **The envelope verification order** (version → message ID → replay window → TTL → size →
  signature) is fixed. Every check is cheap-to-expensive ordered so obviously malformed input is
  rejected before spending cycles on ML-DSA-65 verification.
- **The wire format field order** (bincode, deterministic) is fixed per protocol version. Field
  order changes require a version bump, not a runtime flag.

---

## 9. Testing extension points

Whatever you build on top of `witan`, the
[integration test suite](../../witan/tests/integration_tests.rs) and the
[`wasmtime-test`](../../wasmtime-test/) multi-node harness are good templates for validating your own
extensions — both demonstrate driving the full handshake and gossip lifecycle without a live network,
which is the fastest way to get deterministic coverage of your integration code.
