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

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod cbor;
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
pub mod verifier;
