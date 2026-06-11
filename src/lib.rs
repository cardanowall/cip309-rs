//! Rust SDK for the Label 309 Proof-of-Existence standard.
//!
//! This crate is a byte-parity sibling of the TypeScript (`@cardanowall/sdk-ts`)
//! and Python (`cardanowall-sdk`) SDKs. It independently reproduces the exact
//! canonical-CBOR bytes, validation verdicts, and cryptographic outputs of those
//! implementations, proven against the same shared cross-implementation test
//! vectors.
//!
//! The public surface mirrors the other SDKs: a standalone structural validator,
//! a public verifier, a recipient verifier with sealed-PoE decryption, and a
//! gateway-agnostic HTTP client. Nothing here trusts a publisher or an issuer
//! server; a verifier needs only transaction metadata, optionally the content
//! bytes, and a public blockchain explorer.
//!
//! # Cargo features
//!
//! - **`client`** (default) — the gateway-agnostic HTTP `client` namespace, the
//!   production blocking-`reqwest` transport, and the seed-backed record
//!   `Signer` implementation. This is the only feature that pulls in an HTTP
//!   stack.
//!
//! Building with `--no-default-features` yields a transport-free crate that
//! keeps the entire structural validator, the pure verifier pipeline, the
//! SSRF / deny-host egress guards, and the cryptographic primitives. In that
//! configuration the [`verifier::verify_tx`] entry point has no built-in
//! transport: a caller injects its own
//! [`FetchTransport`](crate::verifier::fetch::FetchTransport) via
//! [`VerifyTxInput::fetch_outbound`](crate::verifier::types::VerifyTxInput).

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod cbor;
#[cfg(feature = "client")]
pub mod client;
pub mod cose;
pub mod hash;
pub mod hex;
pub mod ids;
pub mod kdf;
pub mod merkle;
pub mod poe_standard;
pub mod recipient;
pub mod sealed_poe;
pub mod seed_derive;
pub mod seed_encoding;
pub mod unicode_nfkc16;
mod unicode_nfkc16_data;
pub mod verifier;
