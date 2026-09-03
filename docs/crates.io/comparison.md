# How `witan-gossip` Compares

This page is an honest look at the landscape. If you're evaluating gossip options for a blockchain
validator mesh or a PQC-sensitive peer-to-peer network, here is where the existing tools stand — and
where the gap is that `witan-gossip` fills.

---

## The short version

There is currently no other **free, off-the-shelf, WASM-portable gossip protocol engine with
post-quantum message-level authentication** aimed at blockchain/mesh networks. The closest
alternatives fall into two buckets: mature gossip/transport stacks with **no PQC story at all**, or
PQC primitives with **no gossip protocol wrapped around them**. `witan-gossip` is built at the
intersection of those two buckets.

---

## Feature comparison

| Capability | `witan-gossip` | Raw libp2p (gossipsub) | Tendermint / CometBFT P2P | Raw NATS (Core/JetStream) |
|---|---|---|---|---|
| Post-quantum key exchange (ML-KEM-768) | ✅ Built in, mandatory | ❌ Not available (Noise is classical X25519) | ❌ None | ❌ None |
| Post-quantum signatures (ML-DSA-65) | ✅ Built in, mandatory | ❌ None | ❌ Classical Ed25519 only | ❌ Classical NKeys (Ed25519) only |
| Message-level authenticity (survives relaying) | ✅ Every envelope self-authenticates | ⚠️ Relies on transport-layer security per hop | ⚠️ Relies on transport-layer security per hop | ⚠️ Relies on transport-layer security per hop |
| Epidemic broadcast primitives (dedup, TTL, quorum) | ✅ Built in | ✅ Mature (mesh, fanout) | ✅ Mature (mempool reactor) | ⚠️ Pub/sub only — no dedup/TTL/quorum semantics |
| WASM Component Model portability | ✅ First-class target | ⚠️ Partial WASM support | ❌ Not designed for WASM | ❌ Not designed for WASM |
| Blockchain-agnostic | ✅ No chain assumptions | ✅ Generic | ❌ Cosmos SDK-oriented | ✅ Generic |
| Durable replay of missed messages | — (pair with a broker) | ❌ None natively | ⚠️ Block sync, not gossip replay | ✅ JetStream |
| License | Apache-2.0 OR MIT | Apache-2.0/MIT | Apache-2.0 | Apache-2.0 |
| Core dependency footprint | Small (crypto + protocol only) | Large (full networking stack) | Large (full networking stack) | Moderate (broker server + client) |

---

## Where each competitor is genuinely strong

- **libp2p gossipsub** is battle-tested at internet scale (Ethereum 2.0, IPFS, Filecoin) for
  *epidemic broadcast mechanics* — mesh maintenance, fanout tuning, peer scoring. If you need those
  mechanics and don't need PQC today, it's a mature choice. It is not, however, a PQC solution, and
  retrofitting post-quantum primitives into its Noise-based transport security is a nontrivial,
  unfinished problem industry-wide.
- **Tendermint/CometBFT P2P** is deeply integrated with a specific consensus model and is proven in
  production Cosmos SDK chains. It is not designed to be chain-agnostic, and has no PQC roadmap in
  its core transport.
- **NATS** (Core and JetStream) is an excellent general-purpose messaging system — subject routing,
  clustering, durable streams, and operational tooling that would take significant effort to build
  from scratch. It solves *delivery*, not *cryptographic trust*. Its native auth (NKeys/JWT) is
  classical Ed25519, not post-quantum.

None of these are "bad" — they solve real problems well. They simply solve a **different** problem
than the one `witan-gossip` targets: giving every gossiped message its own quantum-resistant,
self-verifying identity that survives however many hops or brokers it passes through.

---

## The differentiator, stated plainly

Every one of the alternatives above secures the **connection**. `witan-gossip` secures the
**message**. That distinction matters enormously the moment a message is relayed, rebroadcast, or
passed through an intermediary (a broker, a bridge, an untrusted forwarding peer): transport-layer
security (TLS, Noise, or even future hybrid-PQC-TLS) terminates at each hop and must be
re-established and re-trusted at the next one. A `GossipEnvelope` carries its own proof of
authenticity and freshness with it, end to end, independent of how many hops it takes or what
carries it.

Combine that with:

- **PQC as the default, not an add-on** — there's no classical-only code path to accidentally leave
  enabled in production, unlike stacks where PQC is an opt-in transport mode layered on top of an
  otherwise-classical stack.
- **A WASM Component Model core** — the same audited binary embeds in Rust, Go, Python, or behind a
  gRPC boundary, instead of requiring a from-scratch PQC implementation per host language.
- **A minimal, auditable surface** — no bundled networking stack to review, just the cryptographic
  and protocol state machine.

That combination — quantum-resistant, message-level, self-authenticating gossip, delivered as a
portable, dependency-light component — does not currently have a like-for-like free competitor.

---

## When you might *not* want `witan-gossip` (yet)

In the interest of an honest comparison:

- If you need mature, internet-scale peer-scoring and mesh-tuning heuristics *today* and PQC is not
  yet a requirement, libp2p gossipsub's operational track record is longer.
- If you're already deep in the Cosmos SDK ecosystem and don't need PQC or WASM portability,
  Tendermint/CometBFT's P2P layer is the path of least resistance.
- If your primary need is durable, clustered message delivery and cryptographic message identity is
  out of scope for your project, NATS/JetStream alone may be sufficient — though pairing it with
  `witan-gossip` costs you very little and buys you the authenticity guarantee for free.

See [`roadmap.md`](roadmap.md) for where these gaps are headed next.
