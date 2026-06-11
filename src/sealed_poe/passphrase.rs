//! The passphrase key-delivery path: CEK from Argon2id over a normalized
//! passphrase, an in-ciphertext key commitment, and the segmented-STREAM
//! content layer.
//!
//! There is no ephemeral keypair, no per-slot wrap, no trial-decrypt loop, and
//! no on-chain `slots_mac` on this path. The key commitment that `slots_mac`
//! provides on the slots path lives instead in a 32-byte header **inside the
//! ciphertext blob**, prepended before the STREAM chunks:
//!
//! ```text
//! blob = commitment(32) || STREAM chunks
//! ```
//!
//! The commitment is deliberately off-chain: an on-chain commitment would hand
//! every observer a free offline passphrase-test oracle for every passphrase
//! record forever, including records whose ciphertext is withheld. Placing it
//! inside the blob gates guessing on possession of the blob itself.
//!
//! [`passphrase_sealed_poe_open`] verifies the commitment in constant time
//! **before** opening any STREAM chunk; a wrong passphrase, tampered KDF
//! parameters, a tampered header, or a spliced envelope all surface the same
//! single generic rejection (the internal typed classification for every one
//! of them is `TAMPERED_CIPHERTEXT`, indistinguishable by design).

use std::collections::BTreeMap;

use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::kdf::hkdf_sha256;

use super::errors::{EciesSealedPoeError, EciesSealedPoeErrorCode};
use super::normalize::normalize_passphrase;
use super::slots::AEAD_CHACHA20_POLY1305_STREAM64K;
use super::stream::{stream_open, stream_seal, TAG_SIZE};
use super::transcript::{
    compute_passphrase_hash, item_hashes_hash, passphrase_payload_key,
    CARDANO_POE_HKDF_INFO_PASSPHRASE_MAC,
};

/// The sole registered passphrase-KDF identifier under `enc.scheme: 1`.
pub const PASSPHRASE_KDF_ARGON2ID: &str = "argon2id";

/// The key-commitment header prepended to the passphrase-path ciphertext blob.
pub const PASSPHRASE_COMMITMENT_LENGTH: usize = 32;

/// Minimum `enc.passphrase.salt` length in bytes.
pub const MIN_PASSPHRASE_SALT_LENGTH: usize = 16;

/// Maximum `enc.passphrase.salt` length in bytes.
pub const MAX_PASSPHRASE_SALT_LENGTH: usize = 64;

/// Every Argon2id parameter is a wire uint in `0..2^32-1`.
const ARGON2_PARAM_MAX: u64 = u32::MAX as u64;

/// Registry floors for the Argon2id cost parameters. Security is dominated by
/// the `m x t` product; `p >= 1` is a deliberate browser-compatibility floor.
const ARGON2_M_MIN: u64 = 65536;
const ARGON2_T_MIN: u64 = 3;
const ARGON2_P_MIN: u64 = 1;

/// The envelope nonce is always 24 bytes.
const NONCE_LENGTH: usize = 24;

/// The smallest well-formed passphrase-path blob: the 32-byte commitment
/// header plus the lone tag of an empty final STREAM chunk.
const MIN_PASSPHRASE_BLOB_LENGTH: usize = PASSPHRASE_COMMITMENT_LENGTH + TAG_SIZE;

/// Inputs to [`passphrase_sealed_poe_seal`].
///
/// `salt` MUST be freshly drawn from a CSPRNG for every envelope — it is the
/// sole cross-record separator for a reused passphrase. `m`/`t`/`p` are the
/// Argon2id cost parameters exactly as they will appear on the wire; `hashes`
/// is the item's complete content-hash map (algorithm identifier → digest
/// bytes), bound into the commitment.
#[derive(Clone, Copy)]
pub struct PassphraseSealArgs<'a> {
    /// The plaintext to seal.
    pub plaintext: &'a [u8],
    /// The passphrase; normalized under `cardano-poe-pw-norm-v1` before the
    /// KDF.
    pub passphrase: &'a str,
    /// The Argon2id salt (16–64 bytes, fresh per envelope).
    pub salt: &'a [u8],
    /// Argon2id memory cost in KiB.
    pub m: u64,
    /// Argon2id iteration count.
    pub t: u64,
    /// Argon2id parallelism.
    pub p: u64,
    /// The 24-byte envelope-unique nonce.
    pub nonce: &'a [u8],
    /// The item's content-hash map, bound into the commitment.
    pub hashes: &'a BTreeMap<String, Vec<u8>>,
}

/// Inputs to [`passphrase_sealed_poe_open`].
///
/// `aead`, `alg`, `salt`, `m`/`t`/`p`, and `nonce` are taken from the received
/// `enc` map exactly as carried on the wire; `hashes` is the item's
/// content-hash map. The transcript is recomputed from these, so tampering
/// with any of them fails the commitment check.
#[derive(Clone, Copy)]
pub struct PassphraseOpenArgs<'a> {
    /// The ciphertext blob: `commitment(32) || STREAM chunks`.
    pub blob: &'a [u8],
    /// The entered passphrase.
    pub passphrase: &'a str,
    /// The envelope's content-format identifier (`enc.aead`).
    pub aead: &'a str,
    /// The passphrase-KDF identifier (`enc.passphrase.alg`).
    pub alg: &'a str,
    /// The Argon2id salt (`enc.passphrase.salt`).
    pub salt: &'a [u8],
    /// Argon2id memory cost in KiB.
    pub m: u64,
    /// Argon2id iteration count.
    pub t: u64,
    /// Argon2id parallelism.
    pub p: u64,
    /// The 24-byte envelope nonce.
    pub nonce: &'a [u8],
    /// The item's content-hash map.
    pub hashes: &'a BTreeMap<String, Vec<u8>>,
}

/// The outcome of [`passphrase_sealed_poe_open`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PassphraseOpenResult {
    /// The commitment verified and every STREAM chunk authenticated.
    Opened {
        /// The recovered plaintext.
        plaintext: Vec<u8>,
    },
    /// The single generic rejection: a malformed blob, a commitment mismatch
    /// (wrong passphrase, tampered salt / params / header fields, or an
    /// envelope spliced onto a different hash claim), or a STREAM failure.
    /// The causes are indistinguishable by design; the internal typed
    /// classification for all of them is `TAMPERED_CIPHERTEXT`.
    Rejected,
}

impl PassphraseOpenResult {
    /// Whether the open recovered a plaintext.
    #[must_use]
    pub fn opened(&self) -> bool {
        matches!(self, PassphraseOpenResult::Opened { .. })
    }
}

/// Validate the wire-carried KDF inputs shared by seal and open, before any
/// normalization or KDF work: salt bounds, nonce length, each Argon2id
/// parameter a uint within the wire range, then the registry floors
/// (`m >= 65536` KiB, `t >= 3`, `p >= 1`). A below-floor passphrase envelope
/// is categorically outside the construction — it can be neither produced nor
/// opened through this API — so weak-KDF records never enter circulation.
fn assert_kdf_inputs(
    salt: &[u8],
    nonce: &[u8],
    m: u64,
    t: u64,
    p: u64,
) -> Result<(), EciesSealedPoeError> {
    if salt.len() < MIN_PASSPHRASE_SALT_LENGTH {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::EncPassphraseSaltTooShort,
            format!(
                "passphrase salt MUST be at least {MIN_PASSPHRASE_SALT_LENGTH} bytes, got {}",
                salt.len()
            ),
        ));
    }
    if salt.len() > MAX_PASSPHRASE_SALT_LENGTH {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::EncPassphraseSaltTooLong,
            format!(
                "passphrase salt MUST be at most {MAX_PASSPHRASE_SALT_LENGTH} bytes, got {}",
                salt.len()
            ),
        ));
    }
    if nonce.len() != NONCE_LENGTH {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::NonceLengthMismatch,
            format!(
                "envelope nonce MUST be exactly {NONCE_LENGTH} bytes, got {}",
                nonce.len()
            ),
        ));
    }
    for (name, value) in [("m", m), ("t", t), ("p", p)] {
        if value > ARGON2_PARAM_MAX {
            return Err(EciesSealedPoeError::new(
                EciesSealedPoeErrorCode::InvalidPassphraseParams,
                format!("params.{name}={value} outside the wire range 0..{ARGON2_PARAM_MAX}"),
            ));
        }
    }
    if m < ARGON2_M_MIN || t < ARGON2_T_MIN || p < ARGON2_P_MIN {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::EncPassphraseArgon2ParamsTooLow,
            format!(
                "params MUST satisfy m >= {ARGON2_M_MIN}, t >= {ARGON2_T_MIN}, p >= {ARGON2_P_MIN}; got m={m}, t={t}, p={p}"
            ),
        ));
    }
    Ok(())
}

/// Derive the 32-byte CEK: `argon2id(password, salt, {m,t,p}, L=32)`, Argon2
/// version pinned at 0x13 (19). `normalized` is the already-normalized
/// passphrase (`cardano-poe-pw-norm-v1` via [`normalize_passphrase`]) —
/// normalization is a separate, earlier step so its typed rejections fire
/// before any blob-dependent work on the open path. The parameters are
/// validated by [`assert_kdf_inputs`] before this runs, so they always fit a
/// `u32`.
fn argon2_cek(
    normalized: &str,
    salt: &[u8],
    m: u64,
    t: u64,
    p: u64,
) -> Result<[u8; 32], EciesSealedPoeError> {
    let kdf_failed = |detail: String| {
        EciesSealedPoeError::new(EciesSealedPoeErrorCode::KdfDerivationFailed, detail)
    };
    let m = u32::try_from(m).map_err(|_| kdf_failed(format!("argon2id m={m} out of range")))?;
    let t = u32::try_from(t).map_err(|_| kdf_failed(format!("argon2id t={t} out of range")))?;
    let p = u32::try_from(p).map_err(|_| kdf_failed(format!("argon2id p={p} out of range")))?;
    let params =
        Params::new(m, t, p, Some(32)).map_err(|e| kdf_failed(format!("argon2id params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut cek = [0u8; 32];
    argon
        .hash_password_into(normalized.as_bytes(), salt, &mut cek)
        .map_err(|e| kdf_failed(format!("argon2id derivation: {e}")))?;
    Ok(cek)
}

/// The 32-byte key commitment: `HMAC-SHA-256(key = HKDF(CEK, "", passphrase-mac-v1), msg = pw_hash)`.
fn passphrase_commitment(cek: &[u8], pw_hash: &[u8; 32]) -> [u8; 32] {
    let mut mac_key = hkdf_sha256(cek, &[], CARDANO_POE_HKDF_INFO_PASSPHRASE_MAC, 32)
        .expect("32-byte HKDF output is within the RFC 5869 maximum");
    let mut mac =
        <Hmac<Sha256>>::new_from_slice(&mac_key).expect("HMAC accepts a key of any length");
    mac.update(pw_hash);
    let out: [u8; 32] = mac.finalize().into_bytes().into();
    mac_key.zeroize();
    out
}

/// Seal `plaintext` under a passphrase, returning the ciphertext blob
/// `commitment(32) || STREAM chunks`.
///
/// The caller assembles the on-chain `enc` map (`scheme: 1`,
/// `aead: "chacha20-poly1305-stream64k"`, `nonce`, and the
/// `passphrase: { alg: "argon2id", salt, params: {m, t, p} }` block) from the
/// same inputs; nothing in the blob duplicates it.
///
/// # Errors
///
/// Returns an [`EciesSealedPoeError`] for malformed caller input: a salt
/// outside 16–64 bytes, a nonce that is not 24 bytes, a raw passphrase over
/// the input cap, a passphrase that normalizes to the empty string, or
/// Argon2id rejecting its parameters.
pub fn passphrase_sealed_poe_seal(
    args: PassphraseSealArgs<'_>,
) -> Result<Vec<u8>, EciesSealedPoeError> {
    assert_kdf_inputs(args.salt, args.nonce, args.m, args.t, args.p)?;
    let normalized = normalize_passphrase(args.passphrase)?;
    let mut cek = argon2_cek(&normalized, args.salt, args.m, args.t, args.p)?;

    let hashes_hash = item_hashes_hash(args.hashes)?;
    let pw_hash = compute_passphrase_hash(
        AEAD_CHACHA20_POLY1305_STREAM64K,
        args.nonce,
        PASSPHRASE_KDF_ARGON2ID,
        args.salt,
        args.m,
        args.t,
        args.p,
        &hashes_hash,
    );
    let commitment = passphrase_commitment(&cek, &pw_hash);

    let mut payload_key = passphrase_payload_key(&cek, args.nonce);
    cek.zeroize();
    let stream = stream_seal(&payload_key, args.plaintext);
    payload_key.zeroize();

    let mut blob = Vec::with_capacity(PASSPHRASE_COMMITMENT_LENGTH + stream.len());
    blob.extend_from_slice(&commitment);
    blob.extend_from_slice(&stream);
    Ok(blob)
}

/// Open a passphrase-path ciphertext blob.
///
/// Derives the candidate CEK from the entered passphrase, recomputes the
/// commitment over the received header fields and the item's `hashes`, and
/// compares it against the blob's 32-byte header **in constant time, before
/// opening any STREAM chunk**. Every rejection — a blob below the 48-byte
/// well-formedness floor, a commitment mismatch, or a STREAM failure — is the
/// same [`PassphraseOpenResult::Rejected`].
///
/// # Errors
///
/// Returns an [`EciesSealedPoeError`] only for malformed caller input: an
/// unsupported `aead` or `alg` identifier, a salt outside 16–64 bytes, a nonce
/// that is not 24 bytes, a raw passphrase over the input cap, a passphrase
/// that normalizes to the empty string, or Argon2id rejecting its parameters.
pub fn passphrase_sealed_poe_open(
    args: PassphraseOpenArgs<'_>,
) -> Result<PassphraseOpenResult, EciesSealedPoeError> {
    // Typed caller-input rejections fire in a pinned order — the item's hash
    // claim, then passphrase normalization, then the envelope shape — and
    // every one of them strictly precedes any blob-dependent generic failure,
    // so a malformed call is reported the same way whatever blob accompanies
    // it.
    let hashes_hash = item_hashes_hash(args.hashes)?;
    let normalized = normalize_passphrase(args.passphrase)?;

    if args.aead != AEAD_CHACHA20_POLY1305_STREAM64K {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::UnsupportedAeadAlg,
            format!(
                "enc.aead={} unsupported (expected '{AEAD_CHACHA20_POLY1305_STREAM64K}')",
                args.aead
            ),
        ));
    }
    if args.alg != PASSPHRASE_KDF_ARGON2ID {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::EncPassphraseAlgUnsupported,
            format!(
                "enc.passphrase.alg={} unsupported (expected '{PASSPHRASE_KDF_ARGON2ID}')",
                args.alg
            ),
        ));
    }
    assert_kdf_inputs(args.salt, args.nonce, args.m, args.t, args.p)?;

    // A blob below the well-formedness floor (32-byte commitment header plus
    // the lone tag of an empty final chunk) cannot be a passphrase-path
    // ciphertext; rejecting it before the KDF spends no Argon2 work on it.
    // The blob is public input, so the early return reveals nothing.
    if args.blob.len() < MIN_PASSPHRASE_BLOB_LENGTH {
        return Ok(PassphraseOpenResult::Rejected);
    }

    let mut cek = argon2_cek(&normalized, args.salt, args.m, args.t, args.p)?;
    let pw_hash = compute_passphrase_hash(
        args.aead,
        args.nonce,
        args.alg,
        args.salt,
        args.m,
        args.t,
        args.p,
        &hashes_hash,
    );
    let expected = passphrase_commitment(&cek, &pw_hash);
    let header = &args.blob[..PASSPHRASE_COMMITMENT_LENGTH];
    let commitment_ok: bool = expected.ct_eq(header).into();
    if !commitment_ok {
        cek.zeroize();
        return Ok(PassphraseOpenResult::Rejected);
    }

    let mut payload_key = passphrase_payload_key(&cek, args.nonce);
    cek.zeroize();
    let result = match stream_open(&payload_key, &args.blob[PASSPHRASE_COMMITMENT_LENGTH..]) {
        Ok(plaintext) => PassphraseOpenResult::Opened { plaintext },
        Err(_) => PassphraseOpenResult::Rejected,
    };
    payload_key.zeroize();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hashes() -> BTreeMap<String, Vec<u8>> {
        let mut map = BTreeMap::new();
        map.insert("sha2-256".to_string(), vec![0x5au8; 32]);
        map
    }

    fn seal_args<'a>(hashes: &'a BTreeMap<String, Vec<u8>>) -> PassphraseSealArgs<'a> {
        PassphraseSealArgs {
            plaintext: b"sealed body",
            passphrase: "correct horse battery staple",
            salt: &[0x55; 16],
            m: 65536,
            t: 3,
            p: 1,
            nonce: &[0x66; 24],
            hashes,
        }
    }

    #[test]
    fn blob_layout_is_commitment_then_stream() {
        let hashes = hashes();
        let blob = passphrase_sealed_poe_seal(seal_args(&hashes)).unwrap();
        // 32-byte header + (plaintext + 16-byte tag) of a single final chunk.
        assert_eq!(blob.len(), 32 + b"sealed body".len() + 16);
    }

    #[test]
    fn salt_bounds_are_enforced() {
        let hashes = hashes();
        let mut args = seal_args(&hashes);
        args.salt = &[0u8; 15];
        assert_eq!(
            passphrase_sealed_poe_seal(args).unwrap_err().code(),
            "ENC_PASSPHRASE_SALT_TOO_SHORT"
        );
        let long = [0u8; 65];
        let mut args = seal_args(&hashes);
        args.salt = &long;
        assert_eq!(
            passphrase_sealed_poe_seal(args).unwrap_err().code(),
            "ENC_PASSPHRASE_SALT_TOO_LONG"
        );
    }

    #[test]
    fn below_floor_params_are_rejected_before_any_kdf_work() {
        let hashes = hashes();
        let mut args = seal_args(&hashes);
        args.m = 8;
        args.t = 1;
        assert_eq!(
            passphrase_sealed_poe_seal(args).unwrap_err().code(),
            "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW"
        );
        let mut args = seal_args(&hashes);
        args.p = u64::from(u32::MAX) + 1;
        assert_eq!(
            passphrase_sealed_poe_seal(args).unwrap_err().code(),
            "INVALID_PASSPHRASE_PARAMS"
        );
    }

    #[test]
    fn short_blob_is_the_generic_rejection() {
        let hashes = hashes();
        let open = PassphraseOpenArgs {
            blob: &[0u8; 47],
            passphrase: "pw",
            aead: AEAD_CHACHA20_POLY1305_STREAM64K,
            alg: PASSPHRASE_KDF_ARGON2ID,
            salt: &[0x55; 16],
            m: 65536,
            t: 3,
            p: 1,
            nonce: &[0x66; 24],
            hashes: &hashes,
        };
        assert_eq!(
            passphrase_sealed_poe_open(open).unwrap(),
            PassphraseOpenResult::Rejected
        );
    }

    #[test]
    fn open_error_precedence_is_pinned() {
        // Typed caller-input rejections — hash claim, then passphrase
        // normalization, then envelope shape — strictly precede the blob
        // structural floor (which in turn precedes the Argon2id derivation).
        // Each case stacks a later-stage defect under an earlier-stage one and
        // expects the earlier rejection. U+0378 is unassigned in Unicode 16.0,
        // so the pinned normalization profile refuses that passphrase.
        let hashes = hashes();
        let short_blob = [0u8; 47];
        let open_with =
            |passphrase: &'static str, m: u64, t: u64, hashes: &BTreeMap<String, Vec<u8>>| {
                passphrase_sealed_poe_open(PassphraseOpenArgs {
                    blob: &short_blob,
                    passphrase,
                    aead: AEAD_CHACHA20_POLY1305_STREAM64K,
                    alg: PASSPHRASE_KDF_ARGON2ID,
                    salt: &[0x55; 16],
                    m,
                    t,
                    p: 1,
                    nonce: &[0x66; 24],
                    hashes,
                })
            };

        // (1) the hash claim is validated before normalization, envelope, blob.
        let empty_hashes = BTreeMap::new();
        assert_eq!(
            open_with("pass\u{0378}word", 8, 1, &empty_hashes)
                .unwrap_err()
                .code(),
            "ENC_REQUIRES_CONTENT_HASH"
        );
        // (2) normalization is validated before the envelope and the blob.
        assert_eq!(
            open_with("pass\u{0378}word", 8, 1, &hashes)
                .unwrap_err()
                .code(),
            "ENC_PASSPHRASE_UNNORMALIZABLE"
        );
        // (3) the envelope shape is validated before the blob floor.
        assert_eq!(
            open_with("correct horse battery staple", 8, 1, &hashes)
                .unwrap_err()
                .code(),
            "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW"
        );
        // (4) a below-floor blob with well-formed inputs is the generic
        // rejection (the KDF is never reached for it).
        assert_eq!(
            open_with("correct horse battery staple", 65536, 3, &hashes).unwrap(),
            PassphraseOpenResult::Rejected
        );
    }
}
