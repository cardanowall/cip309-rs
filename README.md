# cardanowall — Rust SDK for the Label 309 Proof-of-Existence standard

`cardanowall` is the Rust implementation of the Label 309 Proof-of-Existence (PoE)
toolkit: a standalone structural validator, a public verifier, a recipient
verifier with sealed-PoE decryption, and a gateway-agnostic HTTP client. It is a
**byte-parity sibling** of the TypeScript (`@cardanowall/sdk-ts`) and Python
(`cardanowall-sdk`) SDKs — it independently reproduces the same canonical-CBOR
bytes, validation verdicts, and cryptographic outputs, proven against the same
shared cross-implementation test vectors.

Nothing in this crate trusts a publisher or an issuer server. A proof verifies
from a Cardano transaction's metadata, an optional copy of the content bytes, and
a public blockchain explorer. The HTTP layer is blocking (`reqwest` in blocking
mode) and secure-by-default: every outbound call flows through one egress point
that enforces a protocol/method allowlist, a deny-host policy, bounded response
bodies and timeouts, and an SSRF guard for user-supplied URLs.

The companion `cardanowall` CLI binary is a separate crate built on top of this
SDK.

## What it is

- **A standalone verifier** with three roles, all service-independent:
  - **Structural validator** — `poe_standard::validate_poe_record`, a pure
    function over canonical-CBOR bytes. No I/O, no signatures, no decryption.
  - **Public verifier** — `verifier::verify_tx` resolves a transaction, extracts
    the label-309 record, validates it structurally, and verifies record-level
    signatures.
  - **Recipient verifier** — the public verifier plus an X25519 private key:
    decrypts a sealed PoE and recomputes plaintext hashes.
- **A gateway-agnostic client** (`client::Label309Client`) for any Label 309
  gateway: you pass an explicit base URL and an optional opaque bearer key.
- **The cryptographic building blocks** — hash, KDF, COSE, sealed-PoE,
  recipient encoding, Merkle, and seed-derived identity helpers.

## Install

Pre-1.0 and not yet published to crates.io. Build from the workspace, or depend
on it by path/git:

```toml
# Cargo.toml — by git, until published
[dependencies]
cardanowall = { git = "https://github.com/cardanowall/label-309-rs" }
```

Once published to crates.io the line will be:

```toml
# once published
[dependencies]
cardanowall = "0.1"
```

The crate requires the OS CSPRNG for the secure-by-default sealed-PoE wrap and
uses `rustls` for TLS (no system OpenSSL needed).

## Quick start

### Hash content (byte-identical across the SDK family)

```rust
use cardanowall::hash::{dual_hash, SHA2_256_ID, BLAKE2B_256_ID};
use cardanowall::hex;

let digests = dual_hash(b"contract v3");
println!("{} = {}", SHA2_256_ID, hex::encode(&digests.sha256));
println!("{} = {}", BLAKE2B_256_ID, hex::encode(&digests.blake2b256));
```

For large or streamed input, `hash::dual_hash_stream` computes both digests
without holding the whole input in memory.

### Validate a record structurally (pure, no I/O)

```rust
use cardanowall::poe_standard::{validate_poe_record, ValidateResult};

// `record_bytes` is the canonical-CBOR record, reassembled from the
// label-309 bytes-chunk array (records are tag-259-wrapped on the wire).
match validate_poe_record(&record_bytes) {
    ValidateResult::Valid { record, issues } => {
        // `issues` may carry warnings/info; the record is structurally sound.
        println!("valid record, {} issue(s)", issues.len());
        let _ = record;
    }
    ValidateResult::Invalid { issues } => {
        for issue in issues {
            eprintln!("{}: {}", issue.code.as_str(), issue.message);
        }
    }
}
```

### Verify a transaction end to end (public verifier)

```rust
use cardanowall::verifier::{verify_tx, ExitCode, Verdict, VerifyTxInput};

let mut input = VerifyTxInput::new("aabbccdd…");        // lowercase tx hash, no 0x
input.cardano_gateway_chain = Some(vec![
    "https://api.koios.rest/api/v1".to_string(),
]);

let report = verify_tx(&input);
match report.verdict {
    Verdict::Valid => println!("valid, exit {}", report.exit_code.as_u8()),
    Verdict::Pending => println!("not yet final: {} confirmations", report.num_confirmations),
    Verdict::Failed => eprintln!("failed, exit {}", report.exit_code.as_u8()),
}
assert!(matches!(report.exit_code, ExitCode::Ok | ExitCode::InsufficientDepth | ExitCode::Integrity | ExitCode::Network));
```

`verify_tx` never panics: a malformed record, a missing label-309 entry, or a
gateway failure each produce a `VerifyReport` with the corresponding verdict and
exit code (`0` ok, `1` integrity, `2` network, `3` insufficient depth). The
report carries a per-call HTTP audit trail in `report.http_calls`.

### Recipient verifier: decrypt a sealed PoE

`VerifyTxInput` accepts out-of-band recipient keys; the verifier then decrypts
the sealed item and recomputes the plaintext hashes as part of the verdict:

```rust
use cardanowall::verifier::{verify_tx, Decryption, Verdict, VerifyTxInput};

let mut input = VerifyTxInput::new("aabbccdd…");
input.cardano_gateway_chain = Some(vec!["https://api.koios.rest/api/v1".to_string()]);
input.decryption = Some(vec![Decryption::Recipient {
    item_index: 0,
    recipient_secret_key: recipient_x25519_or_xwing_secret, // Vec<u8>
}]);

let report = verify_tx(&input);
assert_eq!(report.verdict, Verdict::Valid);
```

### Sign a record off-host from a master seed

The seed-derived signer holds the Ed25519 secret in-memory and exposes only the
public key and the 64-byte signature, so the gateway never sees a private key:

```rust
use cardanowall::client::Signer;
use cardanowall::seed_derive::signer_from_seed;

let seed = [0u8; 32];                       // the 32-byte master identity seed
let signer = signer_from_seed(&seed)?;       // SeedDeriveError on wrong length
let pubkey = signer.signer_pubkey();         // raw 32-byte Ed25519 public key
let signature = signer.sign(&sig_structure_bytes)?; // 64-byte Ed25519 signature
# Ok::<(), cardanowall::seed_derive::SeedDeriveError>(())
```

`seed_derive::derive_ed25519_keypair`, `derive_x25519_keypair`, and
`derive_mlkem768x25519_keypair` (hybrid post-quantum X-Wing) expose the same
deterministic identity keys directly.

### Talk to a gateway (any Label 309 deployment)

The client targets no default host. You name the gateway with an explicit
`base_url`; the optional `api_key` is an opaque bearer forwarded verbatim as
`Authorization: Bearer …` (never validated or parsed). With no key the client is
anonymous and read-only.

```rust
use cardanowall::client::{Label309Client, Label309ClientConfig};

let client = Label309Client::new(Label309ClientConfig {
    base_url: Some("https://gateway.example".to_string()),
    api_key: Some("opaque-bearer-token".to_string()),
})?;

let balance = client.account().balance()?;        // AccountBalance
let record = client.records().get("aabbccdd…")?;  // RecordResource, by tx hash
# Ok::<(), Box<dyn std::error::Error>>(())
```

`cardanowall.com` is one example deployment; this SDK works against any gateway
that implements the Label 309 surface. A missing or empty `base_url` is the one
illegal config and raises `InvalidClientConfigError` from the constructor.

## API overview

| Module                                   | Surface                                                                                                                                                                                                       |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hash`                                   | `sha256`, `blake2b256`, `dual_hash`, `dual_hash_stream`; `SHA2_256_ID`, `BLAKE2B_256_ID`                                                                                                                      |
| `poe_standard`                           | `validate_poe_record`, `encode_poe_record`, `encode_record_body_for_signing`, `chunk_bytes` / `bytes_chunk_array_concat`, `chunk_uri` / `reconstruct_chunked_uri`; `PoeRecord`, `ValidateResult`, `ErrorCode` |
| `verifier`                               | `verify_tx`, `VerifyTxInput`, `VerifyReport`, `Verdict`, `ExitCode`, `Profile`, `Decryption`; `verify_record_signatures`, `extract_label_309_metadata`, `resolve_cardano_tx`, `verify_report_to_dict`         |
| `client`                                 | `Label309Client`, `Label309ClientConfig`; namespaces `poe()` / `records()` / `inbox()` / `account()`; `Signer`, off-host signing helpers, `HttpError`, `ProblemDetails`                                       |
| `seed_derive`                            | `signer_from_seed`, `derive_ed25519_keypair`, `derive_x25519_keypair`, `derive_mlkem768x25519_keypair`, `derive_bookmark_key`                                                                                 |
| `sealed_poe`                             | `ecies_sealed_poe_wrap_secure`, `ecies_sealed_poe_unwrap`, `ecies_sealed_poe_trial_decrypt`, envelope/slots/kem/aead                                                                                          |
| `recipient`                              | `encode_age_x25519_recipient`, `encode_age_xwing_recipient`, `parse_age_recipient`, bech32 helpers                                                                                                            |
| `merkle`                                 | `merkle_root`, `merkle_inclusion_proof`, `verify_inclusion`, `encode_leaves_list` / `decode_leaves_list`                                                                                                      |
| `kdf`                                    | `hkdf_sha256`                                                                                                                                                                                                 |
| `cbor`, `cose`, `hex`, `ids`, `webhooks` | canonical CBOR, COSE_Sign1, hex, wire identifiers, webhook signature verification                                                                                                                             |

The crate denies `unsafe_code` and missing docs; `cargo doc` is the exhaustive,
always-current reference.

### Conformance profiles

The verifier reports a record at the highest profile it could check, in strict
superset order: `core` (hash / uris / merkle) → `signed` (adds record-level
`sigs[]`) → `sealed` (adds the `enc` envelope structure) → `recipient-sealed`
(adds byte-level decryption with a recipient key, the default). A lower-profile
verifier that meets a higher-profile field emits an info issue and continues; it
never reports the record invalid.

## Cross-implementation parity

This crate is a **byte-parity twin** of `@cardanowall/sdk-ts` and
`cardanowall-sdk` (Python). The three implementations are tested against the same
shared known-answer-test vectors and a captured mainnet record corpus:

- the **canonical CBOR** of an encoded record is identical bit-for-bit;
- `validate_poe_record` returns the **same verdict and error codes**;
- `verify_tx`'s report serialises (via `verify_report_to_dict`) to the
  **byte-identical JSON** the TS and Python SDKs emit for the same transaction;
- the **seed-derivation** `info` labels and outputs match, so one master seed
  yields the same identity keys in every SDK;
- the sealed-PoE wrap/unwrap and the X-Wing (ML-KEM-768 + X25519) hybrid KEM
  produce identical wire bytes.

Picking Rust, TypeScript, or Python is an ergonomics decision, not a
compatibility one.

## Standard and service independence

A Label 309 proof is verifiable with no cooperation from whoever published it:

1. fetch the transaction's label-309 metadata from any public Cardano explorer;
2. reassemble and structurally validate the record (`validate_poe_record`);
3. verify record-level signatures and, for a sealed PoE, decrypt with the
   recipient key and recompute plaintext hashes.

`verify_tx` performs all three. No issuer server is contacted, and a deny-host
policy lets a verifier prove this by blocking any vendor host outright. The
records are stored on-chain as a CBOR bytes-chunk array under metadata label 309
(tag-259-wrapped); reassemble before validating — the helpers in `poe_standard`
do this for you.

## Relation to the other packages

- **`@cardanowall/crypto-core`** — closed-catalogue cryptographic primitives
  (hash, KDF, signature, KEM, AEAD, CBOR, COSE, sealed-PoE, Merkle, recipient
  encoding, seed derivation). The portable building blocks.
- **`@cardanowall/poe-standard`** — the Label 309 wire-format library: record
  schema, canonical-CBOR encoder, pure structural validator, error-code
  catalogue.
- **`@cardanowall/sdk-ts`** — the browser + Node TypeScript SDK: verifier,
  agnostic client, off-host signing, seed-derived identity helpers.
- **`cardanowall-sdk`** — the Python SDK: a byte-identical parity twin of
  `sdk-ts`.
- **`cardanowall` (this crate)** — the Rust SDK: the byte-parity twin in Rust,
  blocking HTTP, secure-by-default egress. The `cardanowall` CLI is a separate
  crate built on it.

## License

Apache-2.0.
