//! Deterministic key derivation from a single 32-byte master seed.
//!
//! One long-lived master seed deterministically yields every key an identity
//! needs: an Ed25519 signing keypair, an X25519 keypair, and an X-Wing
//! (ML-KEM-768 + X25519 hybrid) keypair. Each derivation is an HKDF-SHA256
//! expansion of the master seed under a distinct, fixed `info` label, so the
//! same seed always reproduces the same keys across the TypeScript
//! (`@cardanowall/sdk-ts`), Python (`cardanowall-sdk`), and this Rust SDK.
//!
//! The `info` labels are part of the protocol: every conformant implementation
//! MUST expand against these exact ASCII bytes, or it derives different keys
//! from the same seed. They are pinned by the shared seed-derivation fixtures.

use ml_kem::array::sizes::U64;
use ml_kem::array::Array;
use ml_kem::{DecapsulationKey, KeyExport, MlKem768};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use thiserror::Error;
use x25519_dalek::x25519;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::kdf::hkdf_sha256;

/// The required master-seed length in bytes.
pub const SEED_LENGTH: usize = 32;

/// The length of each per-key HKDF expansion output in bytes.
const DERIVED_LENGTH: usize = 32;

/// HKDF `info` label for the Ed25519 signing keypair.
pub const INFO_ED25519: &[u8] = b"cardano-poe-ed25519-v1";

/// HKDF `info` label for the X25519 keypair.
pub const INFO_X25519: &[u8] = b"cardano-poe-x25519-v1";

/// HKDF `info` label for the X-Wing (ML-KEM-768 + X25519) hybrid keypair.
pub const INFO_MLKEM768X25519: &[u8] = b"cardano-poe-mlkem768x25519-v1";

/// Serialized length of an X-Wing public key: the 1184-byte ML-KEM-768
/// encapsulation key followed by the 32-byte X25519 public key.
pub const MLKEM768X25519_PUBLIC_KEY_LENGTH: usize = 1216;

/// Length of the FIPS 203 ML-KEM-768 encapsulation key in bytes.
const MLKEM_EK_LENGTH: usize = 1184;

/// Length of the X-Wing SHAKE-256 seed expansion: ML-KEM coins `d ‖ z`
/// (64 bytes) followed by the raw X25519 scalar (32 bytes).
pub const XWING_EXPANDED_SEED_LENGTH: usize = 96;

/// Error raised by the seed-derivation entry points.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SeedDeriveError {
    /// The master seed was not exactly [`SEED_LENGTH`] bytes. Carries the
    /// observed length.
    #[error("seed must be exactly 32 bytes, got {0}")]
    InvalidSeedLength(usize),
}

/// A derived Ed25519 signing keypair.
///
/// The `secret_key` is the raw 32-byte HKDF output, used as the RFC 8032
/// Ed25519 private seed; Ed25519's internal SHA-512 expansion and clamping
/// derive the signing scalar from it. The secret is wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedEd25519KeyPair {
    /// The 32-byte RFC 8032 Ed25519 private seed.
    pub secret_key: [u8; 32],
    /// The 32-byte Ed25519 public key.
    #[zeroize(skip)]
    pub public_key: [u8; 32],
}

/// A derived X25519 keypair.
///
/// The `secret_key` is the raw, **unclamped** 32-byte HKDF output. X25519
/// clamps internally at multiply time, so the stored secret is kept verbatim;
/// pre-clamping it would diverge from the cross-implementation vectors. The
/// secret is wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedX25519KeyPair {
    /// The raw, unclamped 32-byte X25519 secret scalar.
    pub secret_key: [u8; 32],
    /// The 32-byte X25519 public key (clamp applied during the base-point
    /// multiply).
    #[zeroize(skip)]
    pub public_key: [u8; 32],
}

/// A derived X-Wing (ML-KEM-768 + X25519) hybrid keypair.
///
/// Per draft-connolly-cfrg-xwing-kem-06 the secret key IS the 32-byte root
/// seed: the ML-KEM coins and the X25519 scalar are re-expanded from it on
/// demand at decapsulation. The 1216-byte `public_key` is the ML-KEM-768
/// encapsulation key (1184 bytes) followed by the X25519 public key (32 bytes).
/// The secret seed is wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedMlKem768X25519KeyPair {
    /// The 32-byte X-Wing root seed (the secret key).
    pub secret_seed: [u8; 32],
    /// The 1216-byte X-Wing public key (`ek_mlkem ‖ pk_x25519`).
    #[zeroize(skip)]
    pub public_key: [u8; MLKEM768X25519_PUBLIC_KEY_LENGTH],
}

/// Validate the master-seed length and return it as a fixed-size array.
fn checked_seed(seed: &[u8]) -> Result<[u8; SEED_LENGTH], SeedDeriveError> {
    seed.try_into()
        .map_err(|_| SeedDeriveError::InvalidSeedLength(seed.len()))
}

/// Expand the master seed under one `info` label into 32 bytes of key material.
///
/// The salt is empty (the RFC 5869 zero-salt case), matching the reference
/// SDKs. The 32-byte length is well below HKDF's ceiling, so the expansion
/// cannot fail.
fn derive_key_material(seed: &[u8; SEED_LENGTH], info: &[u8]) -> [u8; DERIVED_LENGTH] {
    let okm = hkdf_sha256(seed, &[], info, DERIVED_LENGTH)
        .expect("32-byte HKDF output is well within the RFC 5869 maximum");
    okm.try_into()
        .expect("hkdf_sha256 returns exactly the requested length")
}

/// Derive the Ed25519 signing keypair from the master seed.
///
/// # Errors
///
/// Returns [`SeedDeriveError::InvalidSeedLength`] when `seed` is not exactly
/// [`SEED_LENGTH`] bytes.
pub fn derive_ed25519_keypair(seed: &[u8]) -> Result<DerivedEd25519KeyPair, SeedDeriveError> {
    let seed = checked_seed(seed)?;
    let secret_key = derive_key_material(&seed, INFO_ED25519);
    // The 32-byte HKDF output is the RFC 8032 Ed25519 private seed; dalek's
    // `from_bytes` performs the SHA-512 expand and clamp internally.
    let signing = ed25519_dalek::SigningKey::from_bytes(&secret_key);
    let public_key = signing.verifying_key().to_bytes();
    Ok(DerivedEd25519KeyPair {
        secret_key,
        public_key,
    })
}

/// Derive the X25519 keypair from the master seed.
///
/// The stored secret is the raw, unclamped HKDF output; the public key is the
/// X25519 base-point multiplication of that scalar (which clamps internally).
///
/// # Errors
///
/// Returns [`SeedDeriveError::InvalidSeedLength`] when `seed` is not exactly
/// [`SEED_LENGTH`] bytes.
pub fn derive_x25519_keypair(seed: &[u8]) -> Result<DerivedX25519KeyPair, SeedDeriveError> {
    let seed = checked_seed(seed)?;
    let secret_key = derive_key_material(&seed, INFO_X25519);
    let public_key = x25519_public_key(&secret_key);
    Ok(DerivedX25519KeyPair {
        secret_key,
        public_key,
    })
}

/// Derive the X-Wing (ML-KEM-768 + X25519) hybrid keypair from the master seed.
///
/// The HKDF output is the X-Wing root seed; the keypair is produced by the
/// deterministic X-Wing keygen ([`xwing_keygen`]).
///
/// # Errors
///
/// Returns [`SeedDeriveError::InvalidSeedLength`] when `seed` is not exactly
/// [`SEED_LENGTH`] bytes.
pub fn derive_mlkem768x25519_keypair(
    seed: &[u8],
) -> Result<DerivedMlKem768X25519KeyPair, SeedDeriveError> {
    let seed = checked_seed(seed)?;
    let xwing_seed = derive_key_material(&seed, INFO_MLKEM768X25519);
    let public_key = xwing_keygen(&xwing_seed);
    Ok(DerivedMlKem768X25519KeyPair {
        secret_seed: xwing_seed,
        public_key,
    })
}

/// Compute an X25519 public key from a raw 32-byte secret scalar.
///
/// This is the RFC 7748 base-point multiplication; clamping is applied
/// internally by the X25519 function, so the secret may be (and here is) passed
/// in unclamped.
fn x25519_public_key(secret_scalar: &[u8; 32]) -> [u8; 32] {
    x25519(*secret_scalar, x25519_dalek::X25519_BASEPOINT_BYTES)
}

/// Deterministic X-Wing keygen from a 32-byte root seed.
///
/// Per draft-connolly-cfrg-xwing-kem-06, the seed is expanded with SHAKE-256 to
/// 96 bytes, split as the ML-KEM-768 keygen coins `d ‖ z` (the first 64 bytes)
/// and the X25519 secret scalar (the last 32 bytes). The returned 1216-byte
/// public key is the FIPS 203 ML-KEM-768 encapsulation key (1184 bytes)
/// followed by the X25519 public key (32 bytes). The X-Wing secret key is the
/// input root seed itself, so this returns only the public key; callers that
/// need the keypair use [`derive_mlkem768x25519_keypair`].
#[must_use]
pub fn xwing_keygen(seed: &[u8; SEED_LENGTH]) -> [u8; MLKEM768X25519_PUBLIC_KEY_LENGTH] {
    let mut expanded = expand_xwing_seed(seed);

    // ML-KEM-768 deterministic keygen consumes the 64-byte `d ‖ z` prefix; its
    // `from_seed` splits the 64-byte seed into `d = seed[0..32]`, `z =
    // seed[32..64]` per FIPS 203.
    let mlkem_seed: Array<u8, U64> = Array::try_from(&expanded[0..64])
        .expect("the 96-byte expansion always yields a 64-byte ML-KEM seed prefix");
    let dk = DecapsulationKey::<MlKem768>::from_seed(mlkem_seed);
    let ek_bytes = dk.encapsulation_key().to_bytes();

    // The trailing 32 bytes are the raw, unclamped X25519 scalar.
    let mut x_scalar = [0u8; 32];
    x_scalar.copy_from_slice(&expanded[64..96]);
    let pk_x25519 = x25519_public_key(&x_scalar);

    let mut public_key = [0u8; MLKEM768X25519_PUBLIC_KEY_LENGTH];
    public_key[..MLKEM_EK_LENGTH].copy_from_slice(ek_bytes.as_slice());
    public_key[MLKEM_EK_LENGTH..].copy_from_slice(&pk_x25519);

    // Wipe the intermediate secret material; the caller keeps only the seed.
    expanded.zeroize();
    x_scalar.zeroize();

    public_key
}

/// Expand a 32-byte root seed into the 96-byte X-Wing keygen material via
/// SHAKE-256.
///
/// The 96 output bytes split as the ML-KEM-768 keygen coins `d ‖ z` (the first
/// 64 bytes) and the raw X25519 secret scalar (the last 32 bytes), per
/// draft-connolly-cfrg-xwing-kem-06.
#[must_use]
pub fn expand_xwing_seed(seed: &[u8; SEED_LENGTH]) -> [u8; XWING_EXPANDED_SEED_LENGTH] {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();
    let mut expanded = [0u8; XWING_EXPANDED_SEED_LENGTH];
    reader.read(&mut expanded);
    expanded
}

/// An in-memory path-1 [`Signer`](crate::client::Signer) backed by the master
/// seed.
///
/// The seed-derived Ed25519 secret lives only inside this struct; the publish /
/// off-host-signing path touches just the public key and the 64-byte signature.
/// The 32-byte HKDF output IS the RFC 8032 Ed25519 private seed, so it feeds the
/// dalek signer directly. This is the Rust twin of the TypeScript `signerFromSeed`
/// / Python `signer_from_seed` helper: it lets the CLI and integrators sign a
/// record with the same identity key [`derive_ed25519_keypair`] exposes, without
/// hand-rolling key derivation outside the SDK.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SeedSigner {
    /// The 32-byte RFC 8032 Ed25519 private seed.
    secret_key: [u8; 32],
    /// The 32-byte Ed25519 public key.
    #[zeroize(skip)]
    public_key: [u8; 32],
}

impl SeedSigner {
    /// The 32-byte raw Ed25519 public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
}

impl std::fmt::Debug for SeedSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret seed.
        f.debug_struct("SeedSigner")
            .field("public_key", &hex_public(&self.public_key))
            .finish_non_exhaustive()
    }
}

fn hex_public(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

impl crate::client::Signer for SeedSigner {
    fn signer_pubkey(&self) -> Vec<u8> {
        self.public_key.to_vec()
    }

    fn sign(&self, sig_structure_bytes: &[u8]) -> Result<Vec<u8>, crate::client::SignerError> {
        use ed25519_dalek::{Signer as _, SigningKey};
        let signing = SigningKey::from_bytes(&self.secret_key);
        Ok(signing.sign(sig_structure_bytes).to_bytes().to_vec())
    }
}

/// Build a path-1 [`SeedSigner`] from a 32-byte master identity seed.
///
/// The record-signing Ed25519 key is HKDF-derived from the seed (the same key
/// [`derive_ed25519_keypair`] returns), so a record signed by this signer
/// verifies under the identity that `recipientsFromSeed`-style derivation
/// exposes.
///
/// # Errors
///
/// Returns [`SeedDeriveError::InvalidSeedLength`] when `seed` is not exactly
/// [`SEED_LENGTH`] bytes.
pub fn signer_from_seed(seed: &[u8]) -> Result<SeedSigner, SeedDeriveError> {
    let pair = derive_ed25519_keypair(seed)?;
    Ok(SeedSigner {
        secret_key: pair.secret_key,
        public_key: pair.public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_seed_length() {
        assert_eq!(
            derive_ed25519_keypair(&[0u8; 31]).err(),
            Some(SeedDeriveError::InvalidSeedLength(31)),
        );
        assert_eq!(
            derive_x25519_keypair(&[0u8; 33]).err(),
            Some(SeedDeriveError::InvalidSeedLength(33)),
        );
        assert_eq!(
            derive_mlkem768x25519_keypair(&[]).err(),
            Some(SeedDeriveError::InvalidSeedLength(0)),
        );
    }

    #[test]
    fn info_labels_have_their_protocol_lengths() {
        // These lengths are an invariant of the protocol; the reference SDKs
        // assert them at module load, so we pin them here too.
        assert_eq!(INFO_ED25519.len(), 22);
        assert_eq!(INFO_X25519.len(), 21);
        assert_eq!(INFO_MLKEM768X25519.len(), 29);
    }

    #[test]
    fn x25519_secret_is_stored_unclamped() {
        // A seed whose HKDF output has low bits set would be altered by
        // clamping; the stored secret must keep the raw HKDF bytes verbatim.
        let pair = derive_x25519_keypair(&[7u8; 32]).unwrap();
        let raw = derive_key_material(&[7u8; 32], INFO_X25519);
        assert_eq!(pair.secret_key, raw);
    }

    #[test]
    fn xwing_secret_is_the_root_seed() {
        let xwing_seed = derive_key_material(&[3u8; 32], INFO_MLKEM768X25519);
        let pair = derive_mlkem768x25519_keypair(&[3u8; 32]).unwrap();
        assert_eq!(pair.secret_seed, xwing_seed);
        assert_eq!(pair.public_key.len(), MLKEM768X25519_PUBLIC_KEY_LENGTH);
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = derive_ed25519_keypair(&[1u8; 32]).unwrap();
        let b = derive_ed25519_keypair(&[1u8; 32]).unwrap();
        assert_eq!(a.secret_key, b.secret_key);
        assert_eq!(a.public_key, b.public_key);
    }

    #[test]
    fn seed_signer_pubkey_matches_derivation_and_signs() {
        use crate::client::Signer;
        let seed = [9u8; 32];
        let signer = signer_from_seed(&seed).unwrap();
        let derived = derive_ed25519_keypair(&seed).unwrap();
        assert_eq!(signer.signer_pubkey(), derived.public_key.to_vec());
        // The signature is a deterministic 64 bytes over the message.
        let sig = signer.sign(b"label-309 sig structure").unwrap();
        assert_eq!(sig.len(), 64);
        let sig2 = signer.sign(b"label-309 sig structure").unwrap();
        assert_eq!(sig, sig2);
    }

    #[test]
    fn seed_signer_rejects_wrong_seed_length() {
        assert_eq!(
            signer_from_seed(&[0u8; 31]).err(),
            Some(SeedDeriveError::InvalidSeedLength(31))
        );
    }
}
