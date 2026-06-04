# Crypto-core fixture corpus

## Purpose

This directory is the **byte-pinned conformance gate** between `@cardanowall/crypto-core`
(TypeScript) and `cardanowall-sdk` (Python). Every JSON file is consumed by both the
TS KAT (`*.kat.test.ts`) and the Python KAT (`test_*.py`) tests; divergence between the
two implementations is caught by the repository's parity check.

The KAT vectors and the cross-implementation parity contract are specified by the
Label 309 conformance test-vector corpus.

## Layout

One subdirectory per primitive family:

- `hash/` — SHA-256, BLAKE2b-256, dual-hash equivalence
- `kdf/` — HKDF-SHA-256, Argon2id v1.3, Argon2id parameter constants
- `sig/` — Ed25519 (KAT, roundtrip, ZIP-215 conformance)
- `kem/` — X25519 (RFC 7748 KAT, roundtrip, validation)
- `aead/` — ChaCha20-Poly1305 (RFC 8439) and XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03)
- `cbor/` — canonical CBOR encode/decode (RFC 8949)
- `cose/` — COSE_Sign1 (build + verify + strict-Ed25519 + Sig_structure)
- `discovery/` — passphrase envelope discovery tag (HMAC-SHA-256)
- `sealed-poe/` — multi-recipient sealed-PoE wrap + unwrap (N=1, 3, 32 + negative)
- `seed-derive/` — seed → Ed25519/X25519/X-Wing derivation

One JSON file per scenario (KAT, roundtrip, negative). Naming convention:
`<primitive>-<purpose>.json` (e.g. `sha256-kat.json`, `ed25519-zip215.json`,
`wrap-n32.json`).

## Parity contract

A cross-language parity check enforces SHA-256 byte-identity between this directory
and the Python SDK's mirrored fixture tree. A diverging or missing mirror fails the
check.

## Adding a new fixture

1. Author the JSON on the TypeScript side first (canonical authorship).
2. Mirror it byte-identically to the Python side via `cp -p`.
3. Run the cross-language parity check — it must report every fixture mirrored.
4. Wire the fixture into both the TS `*.kat.test.ts` and the Python `test_*.py`
   consumer.

## Editing an existing fixture

Fixtures are byte-pinned. Any edit requires a corresponding amendment to the
Label 309 conformance test-vector corpus. PRs that change a fixture without a matching
spec edit are review-blocked.

## TS-only carve-outs

The envelope module (`src/envelope/`) has no fixtures because age v1 ciphertexts are
non-deterministic outputs (random file-key, random nonce). The parity script does not
visit `envelope/` because the directory does not exist on either side.

## Negative-path fixtures

`*-negative.json` files exist for `cbor/`, `sealed-poe/`, and `seed-derive/`. They pin
malformed-input error codes; the validator and trial-decrypt tests assert exact
error-code emission.
