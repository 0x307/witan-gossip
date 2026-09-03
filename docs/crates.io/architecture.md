# Architecture: Why the Layers Are Split This Way

This document explains the design boundary between `witan-gossip` (the crypto + protocol engine)
and everything that moves bytes around it (QUIC, TCP, WebTransport, a message broker like NATS via
a companion crate such as `erend-nats`, or your own custom transport). It also gives an honest
account of the risks that this abstraction introduces, because no architectural choice is free.

---

## 1. The boundary

```
┌────────────────────────────────────────────────────────────────────────┐
│                        HOST PROCESS (any language)                     │
│                                                                        │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                   Host Transport Layer                          │   │
│  │   QUIC / TCP / WebTransport / NATS+JetStream / custom           │   │
│  │                                                                 │   │
│  │   recv bytes ──────────────────────────────► send bytes         │   │
│  └──────────────────┬────────────────────────────────┬─────────────┘   │
│                     │ WIT / ABI function calls       │ return bytes    │
│                     ▼                                │                 │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │              witan-gossip (WASM component)                      │   │
│  │                                                                 │   │
│  │   NodeIdentity → PQC Handshake → GossipEngine                   │   │
│  │   (KEM+SIG keys)  (4-message)     (dedup, quorum, TTL, replay)  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
```

The component exports a small set of pure functions (see the
[WIT interface](../../pqc-gossip/wit/gossip-protocol.wit)): given bytes in, it returns bytes out, or
a verdict (`valid` / `GossipError`). It never opens a socket, never spawns a task, never blocks on
I/O. Every side effect that touches the network happens in the host.

---

## 2. What `witan-gossip` provides, alone

- **Node identity** — ML-KEM-768 + X25519 hybrid keypair, ML-DSA-65 keypair, deterministic (from
  supplied seeds) or ephemeral.
- **Mutual PQC handshake** — a 4-message exchange (`HandshakeProbe` → `HandshakeAck` →
  `HandshakeFinish` → `HandshakeFinishAck`) that establishes a session ID via HKDF-SHA256 and proves
  both parties hold the shared KEM secret (HMAC-SHA256 server MAC + ML-DSA-65 transcript signature).
- **Envelope construction and verification** — every `GossipEnvelope` carries the sender's public
  key and an ML-DSA-65 signature over `message_id || payload_type || payload`. Verification is a
  pure function of the bytes; it needs no session state and no network access.
- **Deduplication** — a SHA-256-keyed cache with TTL eviction, so a message flooded through N paths
  is only processed once.
- **Replay protection** — envelopes whose `timestamp_unix_ms` falls outside a configurable window
  are rejected.
- **TTL / hop-count enforcement** — envelopes are dropped once their hop budget is exhausted.
- **BFT quorum tracking** — counts acknowledgements per message and reports when `⌈peers × 2/3⌉` is
  reached.

Everything on this list is a **pure state-machine operation**: JSON/bytes in, JSON/bytes or an error
out. That purity is what makes the WASM Component Model boundary possible in the first place, and
it's also what makes the core small enough to audit properly.

---

## 3. What a transport / messaging layer provides

`witan-gossip` assumes something else is responsible for:

- **Physical connectivity** — opening sockets, TLS/QUIC handshakes at the transport level, keep-alives.
- **Address resolution and connection lifecycle** — knowing which peers exist, connecting, retrying, reconnecting.
- **Byte delivery** — actually getting the bytes returned by `gossip_encode_envelope` /
  `gossip_process_handshake_bytes` onto the wire, and actually getting received bytes back into the
  component via `gossip_verify_envelope` / `gossip_process_handshake_bytes`.
- **Fan-out** — deciding which peers a message goes to. A raw QUIC/TCP host must iterate its peer
  list and send N times; a pub/sub broker (NATS Core, or JetStream for durable subjects) can fan a
  single publish out to every subscriber.
- **Congestion control, retransmission, flow control, NAT traversal** — transport-layer concerns
  that `witan-gossip` has no visibility into and does not need to.
- **Durable persistence and replay** — if a validator is offline for a period, something needs to
  hand it the messages it missed. `witan-gossip`'s dedup cache has a short TTL (default 60s) by
  design; it is not a replay log. A durable stream (e.g., JetStream-style retention) is the natural
  place to solve this.

---

## 4. Why abstract the layers this way?

1. **The component imports no network capability, and you can check that yourself.** Under the
   Component Model a module can only do what its imports allow, and WASI *does* offer sockets
   (`wasi:sockets`) — we simply never import them. The built component declares 17 imports: clocks,
   random, and stdio. None of them can open a connection. So the crypto core cannot leak key
   material onto the network by accident, because it holds no capability to do so:

   ```bash
   wasm-tools component wit target/wasm32-wasip2/release/witan_gossip.wasm | grep import
   ```

   That is a stronger guarantee than "the sandbox forbids it," because it is a property of this
   artifact that you can verify in one command rather than a property you have to take on trust.

2. **A small core is an auditable core.** There is no TLS stack, no async runtime, no libp2p, no
   socket code inside the component that handles your private keys. Every dependency in the crypto
   path is a handful of well-scoped crates (`pqc-kem`, `pqc-sig`, `sha2`, `hkdf`, `hmac`, `bincode`).
   That is a tractable surface for a third-party security review, and a much smaller one than a
   full networking + crypto + consensus stack.

3. **One engine, any transport.** Because the component only deals in bytes, the exact same compiled
   `.wasm` binary works whether the host moves those bytes over raw QUIC, plain TCP, WebTransport in
   a browser, or a message broker such as NATS/JetStream via a companion crate. You are never locked
   into a specific transport choice by the cryptography.

4. **One engine, any host language.** The WIT world means the same binary can be embedded from any
   host with Component Model tooling — Rust via `wasmtime::component`, Go via `wit-bindgen-go`,
   Python via `componentize-py` — with bindings *generated from the interface* rather than
   hand-written per language. No re-implementation of ML-KEM-768/ML-DSA-65 anywhere, which is
   exactly the kind of place cryptography implementations go wrong.

5. **Independent upgrade cadence.** Transport concerns (new QUIC versions, new broker features,
   congestion control tuning) evolve on a completely different timeline than cryptographic
   primitives. Decoupling them means a transport upgrade never requires re-auditing the crypto core,
   and a crypto upgrade (e.g., a future PQC algorithm revision) never requires touching transport
   code.

---

## 5. Challenges and risks of this abstraction

This separation is a deliberate trade-off, not a free lunch. Be aware of the following:

| Risk | Why it happens | What to do about it |
|---|---|---|
| **Host must correctly wire the handshake and verification calls** | The component doesn't enforce call order — a host that skips `gossip_verify_envelope` and processes payload bytes directly bypasses all cryptographic protection | Always verify before trusting: treat `gossip_verify_envelope`/handshake results as your only source of truth about a message's authenticity |
| **No native persistence or replay** | The dedup cache is short-TTL and in-memory; it is not a message log | Pair with a durable transport/broker for high-value payload types (e.g., block proposals, finality votes) if your mesh needs replay for nodes that rejoin after downtime |
| **Delivery guarantees are transport-defined, not protocol-defined** | `witan-gossip` doesn't know if the underlying transport is at-most-once or at-least-once | Understand your transport's delivery semantics; the dedup cache protects you from *duplicate processing*, not from *message loss* |
| **Call-boundary overhead** | Every host↔component interaction marshals bytes across the WASM boundary (WIT bindings or ABI pointer/length pairs) | For most gossip payload sizes and PQC operation costs (ML-DSA-65 sign/verify dominate at single-digit milliseconds) this overhead is negligible, but it is not zero — batch where it makes sense |
| **Version skew across a mesh** | The wire format (bincode field order) and the WIT interface are versioned; a host running a newer/older component than its peers can misinterpret bytes | Treat the WIT package version and `gossip_get_version()` output as a compatibility contract; roll out upgrades in a coordinated fashion across the mesh, the same way you would any consensus-relevant software upgrade |
| **The host owns the peer/mesh topology decisions** | `witan-gossip` tracks *sessions* it has been told about, but fan-out/mesh-membership logic (who to send to) lives in the host | A naive host implementation can under- or over-fan-out; use the `mesh_n` / `mesh_n_low` / `mesh_n_high` config as guidance, and let your transport's native fan-out (e.g., a broker's subject subscribers) do the heavy lifting where available |

The short version: `witan-gossip` guarantees that **if a byte sequence verifies, it is authentic,
fresh, and not a duplicate**. It cannot guarantee that a byte sequence you never gave it — because
your transport dropped it, or your host skipped a verification call — ever arrives or gets checked.
That responsibility is, deliberately, yours.

---

## 6. Pairing with NATS (or `erend-nats`) as a worked example

A message broker like NATS is a natural transport partner because it already solves fan-out,
subject-based routing, and (via JetStream) durable replay — the exact things `witan-gossip`
deliberately leaves out. A typical wiring:

```
gossip_publish(payload_type, payload)          →  message_id
gossip_encode_envelope(payload_type, payload)   →  envelope_bytes
    host: nats.publish(subject_for(payload_type), envelope_bytes)

    ... on every subscriber ...
    host: envelope_bytes = nats.next_message(subscription)
gossip_verify_envelope(envelope_bytes)          →  true / GossipError
```

NATS gives you the "send this to everyone subscribed to `transactions`" behavior; `witan-gossip`
gives you the guarantee that whatever comes out of that subscription is provably from the node it
claims to be from, was signed with a post-quantum-secure key, and hasn't been replayed. Swap NATS for
raw QUIC, TCP, or WebTransport and the two calls to `witan-gossip` don't change at all — only the
host's transport code does.

See [`integration-guide.md`](integration-guide.md) for fuller worked examples.
