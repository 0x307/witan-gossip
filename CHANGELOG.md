# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to the breaking-change and deprecation rules in
[`STABILITY.md`](./STABILITY.md) rather than strict SemVer prior to `1.0.0` — see that
document for what counts as breaking inside `0.x`.

## [Unreleased]

## [0.2.0] — 2026-09-04

### Added

- Program artifacts: `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `STABILITY.md`,
  `NOTICE`, `PROVENANCE.md`, issue templates, and a `cargo-deny` workflow, run in CI weekly
  and on every push.
- Named maintainer recorded in `Cargo.toml` (Ed Johnson); Ken credited as original author.
- `LICENSE-APACHE`, `LICENSE-MIT`, `NOTICE`, and `SECURITY.md` now also ship inside the
  published package (`witan/`), not only at the repo root — `cargo package` cannot include
  files from outside the package directory, so the 0.1.0 `.crate` shipped without them.

### Removed

- **Breaking:** the `native-transport` feature and its four dependencies (`quinn`, `rustls`,
  `rcgen`, `tokio`) — dead code, referenced nowhere in `src/` or `tests/`. If you depended on
  `witan` with `features = ["native-transport"]`, that feature no longer exists; nothing in
  this crate ever used it, so there is no migration — drop the feature from your
  `Cargo.toml`.

### Fixed

- `rand` updated 0.8.5 → 0.8.8, resolving a RUSTSEC advisory for undefined behavior in
  `ThreadRng` (this crate uses `OsRng`, not the affected path, but a PQC crate should not
  carry a flagged RNG regardless).
- Removing `native-transport` also resolved a `cargo-deny` license rejection
  (`CDLA-Permissive-2.0`, pulled in transitively by `quinn`).
- `wasmtime-test` (dev-only, not published) was missing a `license` field.

## [0.1.0] — 2026-09-04

Initial publish.

### Added

- PQC gossip protocol engine: ML-KEM-768 + X25519 hybrid handshake, ML-DSA-65 envelope
  signing and verification, SHA-256 deduplication, BFT quorum tracking, replay protection,
  and TTL hop-count enforcement.
- WASM Component Model interface, exported as `witan:gossip/gossip-protocol@0.1.0`, built for
  `wasm32-wasip2`. `cargo component build` produces an equivalent component via
  `wasm32-wasip1` plus an adapter.
- Native Rust `rlib` for hosts that do not need the WASM sandbox boundary.
- `component` feature (default on) so a crate depending on this one from inside its own
  component can opt out with `default-features = false` and avoid inheriting this crate's
  exported interface into its own world.

### Deprecated

- `wasi-abi` feature — the hand-rolled ptr/len C-ABI (`gossip_*_wasi`) for `wasm32-wasip1`
  core-module hosts. Superseded by the Component Model interface, retained only for consumers
  who integrated against the raw ABI before the component export existed. Scheduled for
  removal; see CRA-9.

### Notes

- `wasm32-unknown-unknown` is not supported: it has no WASI wall clock, so the crate fails to
  build there rather than compiling and then panicking at runtime.
- The cryptographic core has not had a third-party audit. See [`STABILITY.md`](./STABILITY.md)
  for the support posture and [`SECURITY.md`](./SECURITY.md) for how to report a
  vulnerability.
