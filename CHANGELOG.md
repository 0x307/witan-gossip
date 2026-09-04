# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to the breaking-change and deprecation rules in
[`STABILITY.md`](./STABILITY.md) rather than strict SemVer prior to `1.0.0` — see that
document for what counts as breaking inside `0.x`.

## [Unreleased]

### Added

- Program artifacts: `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `STABILITY.md`,
  `NOTICE`, issue templates, and a `cargo-deny` workflow.
- Named maintainer recorded in `Cargo.toml`.

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
