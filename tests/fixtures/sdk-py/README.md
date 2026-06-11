# Python SDK fixture corpus (mirror)

This directory is a **byte-identical mirror** of the `@cardanowall/crypto-core`
TypeScript fixture corpus. Do not author new fixtures here — author on the
TypeScript side first, copy them across byte-for-byte, then verify with the
cross-language parity check.

## Purpose

The corpus is the byte-pinned conformance gate between `cardanowall-sdk` (Python) and
`@cardanowall/crypto-core` (TypeScript). Every JSON file is consumed by the Python
KAT (`test_*.py`) tests and mirrored 1:1 on the TypeScript side. Divergence is caught
by the cross-language parity check that asserts byte-identity between the two trees.

## Layout

One subdirectory per primitive family:

- `hash/` — SHA-256, BLAKE2b-256, dual-hash equivalence
- `kdf/` — HKDF-SHA-256, Argon2id v1.3, Argon2id parameter constants
- `sig/` — Ed25519 (KAT, roundtrip, ZIP-215 conformance)
- `kem/` — X25519 (RFC 7748 KAT, roundtrip, validation)
- `aead/` — ChaCha20-Poly1305 (RFC 8439) and XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03)
- `cbor/` — canonical CBOR encode/decode (RFC 8949)
- `cose/` — COSE_Sign1 (build + verify + strict-Ed25519 + Sig_structure)
- `sealed-poe/` — multi-recipient sealed-PoE wrap + unwrap (N=1, 3, 32 + negative)
- `seed-derive/` — seed → Ed25519/X25519/X-Wing derivation
- `validator/` — structural-validator corpora (negative, positive, role-dependent, bounds)
- `carriage/` — label-309 chunk-array transport + auxiliary-data envelope forms
- `cardano/` — transaction-reference integrity binding + confirmation-depth semantics

`verify-report.schema.json` is the mirrored published verifier-report JSON
Schema, consumed by the report-projection tests.

## Parity contract

The cross-language parity check enforces SHA-256 byte-identity between the
`@cardanowall/crypto-core` fixture corpus (canonical authorship) and this
directory. A diverging or missing mirror turns CI red.

## Adding a new fixture

1. Author the JSON on the TypeScript side first.
2. Mirror it byte-identically to this directory.
3. Run the cross-language parity check — must exit 0.
4. Wire the fixture into the Python `test_*.py` consumer (and the TypeScript
   `*.kat.test.ts` on the canonical side).

## Editing an existing fixture

Fixtures are byte-pinned. Any edit requires regenerating the matching
canonical-source vector and an amendment to the corresponding KAT
specification. PRs that change a fixture without that paper trail are
review-blocked.

## TypeScript-only carve-outs

The envelope module is TypeScript-only and has no Python counterpart. The
parity check does not visit `envelope/` because the directory does not exist
on either side.

## Negative-path fixtures

`*-negative.json` files exist for `cbor/`, `sealed-poe/`, and `seed-derive/`. They pin
malformed-input error codes; the validator and trial-decrypt tests assert exact
error-code emission.
