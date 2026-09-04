# Provenance

Charter §3 of the 0x307 release bar requires a provenance answer recorded in writing. This
is it, for this repository.

## Ownership

**0x307 Inc. owns this work.** Not an individual, not SAGP LLC. The
`Copyright (c) 2026 0x307 Inc.` line in `LICENSE-MIT` and `LICENSE-APACHE` is correct as
published, and `NOTICE` carries the same statement.

The IP reached 0x307 Inc. by transfer from Aytch4k. 0x307 Inc. is the owner outright, not a
licensee.

## Authorship vs. maintainership

These are two different things and are recorded separately on purpose.

- **Ken is the original author.** The gossip protocol, the PQC handshake construction, and
  the cryptographic core are his work.
- **Ed Johnson is the named maintainer.** That means he is the human behind
  `security@0x307.com` for this repository and the response window in
  [`SECURITY.md`](SECURITY.md). It is not a claim of authorship.

Do not infer authorship from the maintainer line, or maintainership from the author line.

## Downstream use

A client engagement builds on this crate downstream. That work is a *consumer* of this
repository, not its origin — the direction is 0x307 Inc. → client build, not the reverse.

## Dependencies

Dependency licensing is checked by `cargo deny` (see `deny.toml`) and runs in CI. One
advisory is accepted deliberately with its reasoning recorded inline in that file:
`RUSTSEC-2025-0141`, bincode 1.x unmaintained, which cannot be resolved without a wire-format
change affecting every node in a mesh.
