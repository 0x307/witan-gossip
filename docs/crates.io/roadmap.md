# Roadmap

`witan-gossip` ships today as a focused, auditable core: PQC handshake, envelope sign/verify,
dedup, quorum tracking, replay protection, and TTL enforcement, as a WASM Component with Rust/Go/
Python/gRPC embedding paths. Here is where it's headed next — the obvious, high-value directions
that follow naturally from that foundation.

None of this is a promise of dates; it's a statement of direction, so integrators can plan around
where the crate is going.

---

## Near-term

- **Finish the Go and Python ABI bindings.** The calling convention and stub files already exist in
  [`pqc-gossip/abi/`](../../pqc-gossip/abi/); hardening them to production quality (error mapping,
  memory-safety review, packaging) is the most immediately useful next step for non-Rust hosts.
- **A reference gRPC server.** Turning [`gossip.proto`](../../pqc-gossip/abi/proto/gossip.proto)
  into a runnable service means *any* language with a gRPC client can talk to `witan-gossip`
  without touching WASM at all — useful for teams that want the engine as a sidecar process rather
  than an embedded library.
- **Conformance test vectors.** A published set of known-good handshake transcripts and envelope
  fixtures so integrators can verify their host wiring produces byte-for-byte compatible output
  against the reference implementation — catching integration bugs before they hit a live mesh.
- **Native sidecar packaging.** A small standalone binary that embeds the engine and exposes it over
  a local socket, for teams that want the crypto core without adding a WASM runtime dependency to
  their main service.

---

## Medium-term

- **Algorithm diversity.** Support for an alternative post-quantum signature scheme (such as a
  hash-based signature standard) as a configurable option alongside ML-DSA-65 — giving operators a
  fallback signature family in case of an unexpected cryptanalytic advance against lattice-based
  schemes, which is exactly the kind of algorithm-agility that "post-quantum by default" should
  mean in practice.
- **Reference transport adapters, published separately.** Worked, best-practice example crates that
  wire `witan-gossip` to common transports (a QUIC adapter, a NATS/JetStream adapter) — kept as
  separate, optional crates so the audited core stays minimal, while integrators get a proven
  starting point instead of writing the wiring from scratch.
- **Pluggable replay/catch-up hook.** An optional trait-like extension point so long-lived meshes
  can plug in a durable store for messages missed during downtime, complementing (not replacing) the
  built-in short-TTL dedup cache.
- **Observability exporters.** Prometheus/OpenTelemetry adapters that turn `gossip_get_stats()` into
  metrics your existing dashboards already understand.
- **Third-party security audit.** A published, independent audit report of the cryptographic core,
  plus a continuous fuzzing corpus for the envelope and handshake parsers.

---

## Longer-term direction

- **Component registry publishing.** Making the compiled component discoverable through emerging
  WASM Component Model registries, so hosts can pull a versioned, signed binary instead of building
  from source.
- **Key management integrations.** Worked examples of sourcing `kem_seed_hex`/`sig_seed_hex` from
  common HSM/KMS providers, building on the deterministic-identity seed mechanism that already
  exists today.
- **Browser-native builds.** A `wasm-bindgen`-targeted build alongside the existing Component Model
  target, so browser/WASM clients can use the engine directly without a host-side proxy.

---

## Why this roadmap, and not something else

Every item above extends the *edges* of the system — bindings, adapters, observability, packaging,
algorithm agility — without growing the audited crypto core itself. That's a deliberate choice: the
value of a small, auditable trust boundary compounds over time, and the fastest way to lose it is to
keep adding "just one more feature" directly into the component that holds your private keys. The
roadmap grows what surrounds the core; it does not grow the core.

If there's a direction you need that isn't listed here, [open an issue](https://github.com/witan-gossip/witan-gossip)
— integrator feedback is the main input to how this list gets reordered.
