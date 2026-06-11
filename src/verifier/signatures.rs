//! Label 309 record-level signature verification.
//!
//! One verification per `record.sigs[i]`. v1 has NO per-item signature slot —
//! the only signature surface is the record-level array. The signed payload is
//! `utf8("cardano-poe-record-sig-v1") || canonical_cbor(record_body_without_sigs)`;
//! the COSE primitive in [`crate::cose`] prepends the domain prefix, uses the
//! producer's protected-header bytes VERBATIM as `Sig_structure[1]` (never a
//! re-encode), and handles CIP-8 hashed mode internally. Ed25519 verification
//! is strict per RFC 8032 §5.1.7 (canonical R/S, low-order rejection, no
//! cofactor multiplication).
//!
//! Two mutually-exclusive signer-key paths (the structural validator rejects a
//! record carrying both):
//!
//! - **Path 1** — a 32-byte protected-header `kid` is the raw Ed25519 pubkey.
//! - **Path 2** — a `sigs[i].cose_key` COSE_Key blob carries the wallet pubkey,
//!   and the protected header binds a 29-byte CIP-19 stake `address`. The
//!   verifier recomputes `network_header || Blake2b-224(pubkey)` — deriving the
//!   network byte from the CONTAINING TRANSACTION's network, never echoing the
//!   byte found in the record — and rejects on any of the 29 bytes.
//!
//! Record signatures are OPTIONAL: a public hash-only PoE remains valid even
//! when every signature entry is unverifiable (`SIGNATURE_UNSUPPORTED`, info).

use blake2::digest::consts::U28;
use blake2::{Blake2b, Digest};
use subtle::ConstantTimeEq;

use crate::cbor::CborValue;
use crate::cose::{
    cose_sign1_label309_verify, decode_cose_sign1, parse_cose_key_ed25519, CoseSign1Decoded,
    CoseVerifyErrorCode, CoseVerifyResult,
};
use crate::poe_standard::{encode_record_body_for_signing, PoeRecord, SigEntry};

use crate::verifier::types::{CardanoNetwork, SigFailureReason, SignatureCheck, SignerType};

/// CIP-19 mainnet stake-address network header byte.
const CIP19_STAKE_NETWORK_HEADER_MAINNET: u8 = 0xe1;
/// CIP-19 preprod/testnet stake-address network header byte.
const CIP19_STAKE_NETWORK_HEADER_PREPROD: u8 = 0xe0;
/// Length of a CIP-19 stake (reward) address: header byte + 28-byte key hash.
const CIP19_STAKE_ADDRESS_LENGTH: usize = 29;
/// Length of an Ed25519 public key.
const ED25519_PUBLIC_KEY_LENGTH: usize = 32;

/// Compute the 28-byte BLAKE2b-224 digest used for stake-key hashing.
fn blake2b224(data: &[u8]) -> [u8; 28] {
    Blake2b::<U28>::digest(data).into()
}

/// Verify every `record.sigs[i]` entry, in order, against the containing
/// transaction's `network`.
#[must_use]
pub fn verify_record_signatures(
    record: &PoeRecord,
    network: CardanoNetwork,
) -> Vec<SignatureCheck> {
    // The signed body is canonical CBOR of the record minus `sigs`. The encoder
    // cannot fail here (a record that validated has no duplicate extension
    // keys), but a defensive empty body still produces deterministic per-entry
    // failures.
    let record_body = encode_record_body_for_signing(record).unwrap_or_default();
    let sigs = record.sigs.as_deref().unwrap_or(&[]);
    sigs.iter()
        .enumerate()
        .map(|(i, entry)| verify_one(i, entry, &record_body, network))
        .collect()
}

fn verify_one(
    index: usize,
    entry: &SigEntry,
    record_body: &[u8],
    network: CardanoNetwork,
) -> SignatureCheck {
    let cose_bytes = entry.cose_sign1.as_slice();
    let Ok(cose) = decode_cose_sign1(cose_bytes) else {
        return SignatureCheck {
            index,
            valid: false,
            signer_pub: None,
            signer_type: None,
            reason: Some(SigFailureReason::MalformedSigCoseSign1),
        };
    };

    // Resolve the signer key (path 1 vs path 2) before the cryptographic
    // verify, so an unresolved key is reported as such rather than as an
    // invalid signature.
    let Some((pub_key, signer_type)) = resolve_signer_key(&cose, entry) else {
        return SignatureCheck {
            index,
            valid: false,
            signer_pub: None,
            signer_type: None,
            reason: Some(SigFailureReason::SignerKeyUnresolved),
        };
    };

    // Strict Ed25519 verify over the verbatim protected bytes; the helper also
    // enforces the detached-payload rule, the EdDSA `alg`, and CIP-8 hashed
    // mode.
    let verify_result = cose_sign1_label309_verify(cose_bytes, record_body, Some(&pub_key));
    if let CoseVerifyResult::Err(code) = verify_result {
        return SignatureCheck {
            index,
            valid: false,
            signer_pub: Some(crate::hex::encode(&pub_key)),
            signer_type: Some(signer_type),
            reason: Some(map_verify_error(code)),
        };
    }

    // Path-2 wallet address binding. Path-1 entries skip this entirely.
    if signer_type == SignerType::WalletInlineKey
        && !wallet_address_binds_pubkey(&cose, &pub_key, network)
    {
        return SignatureCheck {
            index,
            valid: false,
            signer_pub: Some(crate::hex::encode(&pub_key)),
            signer_type: Some(signer_type),
            reason: Some(SigFailureReason::WalletAddressMismatch),
        };
    }

    SignatureCheck {
        index,
        valid: true,
        signer_pub: Some(crate::hex::encode(&pub_key)),
        signer_type: Some(signer_type),
        reason: None,
    }
}

/// Resolve the 32-byte signer pubkey and its path.
///
/// Path 1 applies when the protected header carries a 32-byte `kid` and the
/// entry carries no `cose_key`; an entry with a `cose_key` resolves through
/// path 2 (the two are mutually exclusive on a validated record). Unprotected
/// `kid` values are never consulted: they sit outside the COSE integrity
/// envelope and an attacker could rewrite them.
fn resolve_signer_key(cose: &CoseSign1Decoded, entry: &SigEntry) -> Option<([u8; 32], SignerType)> {
    if entry.cose_key.is_none() {
        if let Some(kid) = cose.protected_header.kid() {
            return Some((kid, SignerType::InSignatureKid));
        }
        return None;
    }
    if let Some(blob) = &entry.cose_key {
        if let Some(pub_key) = parse_cose_key_ed25519(blob) {
            return Some((pub_key, SignerType::WalletInlineKey));
        }
    }
    None
}

/// Map a COSE verify error code to the verifier's signature-failure reason.
fn map_verify_error(code: CoseVerifyErrorCode) -> SigFailureReason {
    match code {
        CoseVerifyErrorCode::MalformedSigCose | CoseVerifyErrorCode::MalformedSigCoseSign1 => {
            SigFailureReason::MalformedSigCoseSign1
        }
        CoseVerifyErrorCode::UnsupportedSigAlg => SigFailureReason::SignatureUnsupported,
        CoseVerifyErrorCode::KidUnresolved => SigFailureReason::SignerKeyUnresolved,
        CoseVerifyErrorCode::SignatureInvalid => SigFailureReason::SignatureInvalid,
    }
}

/// Recompute `network_header || Blake2b-224(pubkey)` and compare it
/// constant-time to the path-2 protected-header `address` claim.
///
/// v1 binds the wallet path to 29-byte CIP-19 stake addresses only; a missing,
/// non-bytes, wrong-length, or wrong-network-header claim fails (`address` is
/// REQUIRED on the wallet path — a wallet signature without an address claim
/// cannot be safely surfaced as wallet-bound).
fn wallet_address_binds_pubkey(
    cose: &CoseSign1Decoded,
    pub_key: &[u8; 32],
    network: CardanoNetwork,
) -> bool {
    let network_byte = match network {
        CardanoNetwork::Mainnet => CIP19_STAKE_NETWORK_HEADER_MAINNET,
        CardanoNetwork::Preprod => CIP19_STAKE_NETWORK_HEADER_PREPROD,
    };
    let Some(address) = protected_header_address(cose) else {
        return false;
    };
    if address.len() != CIP19_STAKE_ADDRESS_LENGTH {
        return false;
    }
    let key_hash = blake2b224(pub_key);
    let mut derived = [0u8; CIP19_STAKE_ADDRESS_LENGTH];
    derived[0] = network_byte;
    derived[1..].copy_from_slice(&key_hash);
    derived.ct_eq(address.as_slice()).unwrap_u8() == 1
}

/// Read the protected-header `"address"` byte string, if present.
fn protected_header_address(cose: &CoseSign1Decoded) -> Option<Vec<u8>> {
    let CborValue::Map(pairs) = cose.protected_header.to_cbor() else {
        return None;
    };
    for (key, value) in pairs {
        if let CborValue::Text(s) = &key {
            if s == "address" {
                if let CborValue::Bytes(b) = value {
                    return Some(b);
                }
            }
        }
    }
    None
}

// `ED25519_PUBLIC_KEY_LENGTH` documents the resolved-key length invariant; the
// COSE helpers already enforce it, so it is referenced only in an assertion.
const _: () = assert!(ED25519_PUBLIC_KEY_LENGTH == 32);
