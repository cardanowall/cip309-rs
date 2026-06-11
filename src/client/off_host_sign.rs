//! Label 309 v1 off-host signing helper.
//!
//! The signing key never enters this module: it touches only public data — the
//! record bytes and the 32-byte signer public key on the way in, the canonical
//! `Sig_structure` bytes on the way out, and the 64-byte Ed25519 signature on
//! the way back. The integrator's signer callback owns the private key (in-memory,
//! AWS KMS, GCP HSM, YubiHSM, or an air-gapped offline workstation reached over
//! QR / USB).
//!
//! Wire-format invariants this module enforces:
//!
//! - `to_sign = utf8("cardano-poe-record-sig-v1") || canonical_cbor(record_body_minus_sigs)`;
//!   the 25-byte domain prefix is prepended internally.
//! - `Sig_structure = ["Signature1", body_protected, h'' /* empty aad */, to_sign]`.
//! - Path-1 protected header `{1: -8, 4: <signer_pubkey>}` — canonical CBOR is
//!   always the 38 bytes `a2 01 27 04 58 20 || <32-byte pubkey>`.
//! - `COSE_Sign1 = [protected, unprotected, null, signature]` — detached payload,
//!   `alg = -8` (EdDSA). The result is chunked into the `[ bstr .size (1..64) ]`
//!   array and placed in `sigs[0]`.
//! - CIP-8 `hashed = true` mode substitutes `Sig_structure[3]` with
//!   `BLAKE2b-224(to_sign)` and adds the text key `"hashed": true` to the
//!   unprotected header. It is intended only for hardware co-signers with screen
//!   / buffer constraints; software signers use the non-hashed mode.

use blake2::digest::consts::U28;
use blake2::digest::Digest;
use blake2::Blake2b;

use crate::cbor::CborValue;
use crate::cose::{
    build_label309_sig_structure, build_sig_structure, encode_cose_sign1, CoseHeader,
    CARDANO_POE_SIG_DOMAIN_PREFIX,
};
use crate::poe_standard::{encode_record_body_for_signing, PoeRecord, SigEntry};

const ED25519_PUBLIC_KEY_LENGTH: usize = 32;
const ED25519_SIGNATURE_LENGTH: usize = 64;
const COSE_HEADER_ALG_LABEL: i64 = 1;
const COSE_HEADER_KID_LABEL: i64 = 4;
const HASHED_MODE_HEADER_KEY: &str = "hashed";
/// EdDSA, the only signature algorithm Label 309 v1 records carry.
const COSE_ALG_EDDSA: i64 = -8;

/// A validation failure raised by the off-host signing helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OffHostSignError {
    /// The signer public key was not exactly 32 bytes.
    #[error("INVALID_PUBKEY_LENGTH: signerPubkey must be 32 bytes (Ed25519 raw public key)")]
    InvalidPubkeyLength,
    /// The signature was not exactly 64 bytes.
    #[error("INVALID_SIGNATURE_LENGTH: signature must be 64 bytes (Ed25519 raw signature)")]
    InvalidSignatureLength,
}

impl OffHostSignError {
    /// The stable discriminator code for this error.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            OffHostSignError::InvalidPubkeyLength => "INVALID_PUBKEY_LENGTH",
            OffHostSignError::InvalidSignatureLength => "INVALID_SIGNATURE_LENGTH",
        }
    }
}

/// The result of [`prepare_sig_structure`]: the bytes the signer signs, plus the
/// canonical protected-header bytes (always 38 bytes) for fixture comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedSigStructure {
    /// The canonical-CBOR `Sig_structure` the signer feeds verbatim to Ed25519.
    pub sig_structure_bytes: Vec<u8>,
    /// The canonical-CBOR protected-header bytes (38 bytes for path-1).
    pub protected_header_bytes: Vec<u8>,
}

/// The result of [`prepare_sig_structure_hashed`]: as [`PreparedSigStructure`]
/// plus the 28-byte `BLAKE2b-224(to_sign)` that replaces `Sig_structure[3]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedSigStructureHashed {
    /// The canonical-CBOR `Sig_structure` (over the 28-byte hash).
    pub sig_structure_bytes: Vec<u8>,
    /// The canonical-CBOR protected-header bytes (identical to the non-hashed
    /// path).
    pub protected_header_bytes: Vec<u8>,
    /// The 28-byte `BLAKE2b-224(to_sign)`.
    pub to_sign_hash_bytes: Vec<u8>,
}

/// The result of [`assemble_cose_sign1`]: the full COSE_Sign1 bytes and the
/// chunked `sigs[]` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembledCoseSign1 {
    /// The full canonical-CBOR COSE_Sign1 bytes.
    pub cose_sign1_bytes: Vec<u8>,
    /// The `sigs[i]` entry carrying the chunked COSE_Sign1.
    pub sig_entry: SigEntry,
}

/// Compute the 28-byte BLAKE2b-224 digest CIP-8 hashed mode signs.
fn blake2b224(input: &[u8]) -> [u8; 28] {
    Blake2b::<U28>::digest(input).into()
}

/// Build `to_sign = utf8("cardano-poe-record-sig-v1") || record_body_cbor`.
///
/// The first 25 bytes are the fixed domain prefix; the remainder is the
/// canonical CBOR of the record body with `sigs` removed.
///
/// # Errors
///
/// Returns the canonical-encoder error only if the record carries two extension
/// keys with byte-identical canonical encodings.
pub fn build_to_sign(record: &PoeRecord) -> Result<Vec<u8>, crate::cbor::CanonicalCborError> {
    let body = encode_record_body_for_signing(record)?;
    let prefix = CARDANO_POE_SIG_DOMAIN_PREFIX.as_bytes();
    let mut out = Vec::with_capacity(prefix.len() + body.len());
    out.extend_from_slice(prefix);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Build the canonical path-1 protected header `{1: -8, 4: <signer_pubkey>}`.
fn path1_protected_header(signer_pubkey: &[u8]) -> CoseHeader {
    CoseHeader::new()
        .with_int(COSE_HEADER_ALG_LABEL, CborValue::int(COSE_ALG_EDDSA))
        .with_int(
            COSE_HEADER_KID_LABEL,
            CborValue::bytes(signer_pubkey.to_vec()),
        )
}

/// The canonical-CBOR bytes of the path-1 protected header (always 38 bytes).
fn path1_protected_header_bytes(signer_pubkey: &[u8]) -> Vec<u8> {
    // The header carries two distinct integer labels, so canonical encoding
    // cannot hit the duplicate-key error.
    path1_protected_header(signer_pubkey)
        .encode_protected()
        .expect("path-1 protected header encodes")
}

/// Build the canonical `Sig_structure` the off-host signer signs.
///
/// # Errors
///
/// [`OffHostSignError::InvalidPubkeyLength`] when `signer_pubkey` is not 32
/// bytes. The canonical-encoder error is never produced here (the record body
/// is re-encoded by [`build_to_sign`], whose duplicate-key case is impossible
/// for a record that round-trips).
pub fn prepare_sig_structure(
    record: &PoeRecord,
    signer_pubkey: &[u8],
) -> Result<PreparedSigStructure, OffHostSignError> {
    if signer_pubkey.len() != ED25519_PUBLIC_KEY_LENGTH {
        return Err(OffHostSignError::InvalidPubkeyLength);
    }
    let protected_header_bytes = path1_protected_header_bytes(signer_pubkey);
    let record_body_cbor = encode_record_body_for_signing(record).unwrap_or_default();
    let sig_structure_bytes =
        build_label309_sig_structure(&protected_header_bytes, &record_body_cbor);
    Ok(PreparedSigStructure {
        sig_structure_bytes,
        protected_header_bytes,
    })
}

/// Assemble the detached path-1 COSE_Sign1 and its `sigs[]` entry.
///
/// # Errors
///
/// [`OffHostSignError::InvalidPubkeyLength`] / [`OffHostSignError::InvalidSignatureLength`]
/// on a wrong-length public key or signature.
pub fn assemble_cose_sign1(
    record: &PoeRecord,
    signer_pubkey: &[u8],
    signature: &[u8],
) -> Result<AssembledCoseSign1, OffHostSignError> {
    let _ = record;
    if signer_pubkey.len() != ED25519_PUBLIC_KEY_LENGTH {
        return Err(OffHostSignError::InvalidPubkeyLength);
    }
    if signature.len() != ED25519_SIGNATURE_LENGTH {
        return Err(OffHostSignError::InvalidSignatureLength);
    }
    let protected_header = path1_protected_header(signer_pubkey);
    // Empty unprotected header, detached (null) payload, EdDSA. The header maps
    // carry no duplicate keys, so canonical encoding cannot fail.
    let cose_sign1_bytes =
        encode_cose_sign1(&protected_header, &CoseHeader::new(), None, signature)
            .expect("COSE_Sign1 encodes");
    Ok(AssembledCoseSign1 {
        sig_entry: SigEntry {
            cose_sign1: cose_sign1_bytes.clone(),
            cose_key: None,
        },
        cose_sign1_bytes,
    })
}

/// CIP-8 `hashed = true` companion to [`prepare_sig_structure`].
///
/// Substitutes `Sig_structure[3]` with `BLAKE2b-224(to_sign)`. The hash covers
/// the entire `to_sign` payload — including the 25-byte domain prefix — so
/// cross-protocol replay protection survives hashed mode. Discouraged for
/// software signers.
///
/// # Errors
///
/// [`OffHostSignError::InvalidPubkeyLength`] when `signer_pubkey` is not 32
/// bytes.
pub fn prepare_sig_structure_hashed(
    record: &PoeRecord,
    signer_pubkey: &[u8],
) -> Result<PreparedSigStructureHashed, OffHostSignError> {
    if signer_pubkey.len() != ED25519_PUBLIC_KEY_LENGTH {
        return Err(OffHostSignError::InvalidPubkeyLength);
    }
    let protected_header_bytes = path1_protected_header_bytes(signer_pubkey);
    let to_sign = build_to_sign(record).unwrap_or_default();
    let to_sign_hash = blake2b224(&to_sign);
    let sig_structure_bytes = build_sig_structure(&protected_header_bytes, &[], &to_sign_hash);
    Ok(PreparedSigStructureHashed {
        sig_structure_bytes,
        protected_header_bytes,
        to_sign_hash_bytes: to_sign_hash.to_vec(),
    })
}

/// Assemble a hashed-mode COSE_Sign1 carrying the unprotected `"hashed": true`
/// text-key flag.
///
/// # Errors
///
/// [`OffHostSignError::InvalidPubkeyLength`] / [`OffHostSignError::InvalidSignatureLength`]
/// on a wrong-length public key or signature.
pub fn assemble_cose_sign1_hashed(
    record: &PoeRecord,
    signer_pubkey: &[u8],
    signature: &[u8],
) -> Result<AssembledCoseSign1, OffHostSignError> {
    let _ = record;
    if signer_pubkey.len() != ED25519_PUBLIC_KEY_LENGTH {
        return Err(OffHostSignError::InvalidPubkeyLength);
    }
    if signature.len() != ED25519_SIGNATURE_LENGTH {
        return Err(OffHostSignError::InvalidSignatureLength);
    }
    let protected_header = path1_protected_header(signer_pubkey);
    let unprotected_header =
        CoseHeader::new().with_text(HASHED_MODE_HEADER_KEY, CborValue::Bool(true));
    let cose_sign1_bytes =
        encode_cose_sign1(&protected_header, &unprotected_header, None, signature)
            .expect("COSE_Sign1 encodes");
    Ok(AssembledCoseSign1 {
        sig_entry: SigEntry {
            cose_sign1: cose_sign1_bytes.clone(),
            cose_key: None,
        },
        cose_sign1_bytes,
    })
}
