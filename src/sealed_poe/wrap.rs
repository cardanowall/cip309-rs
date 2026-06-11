//! Multi-recipient sealed-PoE wrap: age-style ECIES (classical X25519) and
//! the X-Wing hybrid KEM, both producing one envelope shape.
//!
//! A sealed PoE encrypts its plaintext ONCE under a random content-encryption
//! key (CEK) in the `chacha20-poly1305-stream64k` segmented STREAM format,
//! then wraps that CEK to each recipient in a per-recipient slot. The two KEM
//! branches share the envelope shape and are discriminated by the envelope
//! `kem` field:
//!
//! - `x25519`: classical age-style ECIES. Each slot carries a 32-byte
//!   ephemeral public key (`epk`) and the 48-byte wrapped CEK (`wrap`).
//! - `mlkem768x25519`: X-Wing hybrid. Each slot carries the 1120-byte X-Wing
//!   ciphertext (`kem_ct`, a single byte string) and the 48-byte wrapped CEK.
//!   No per-slot `epk`.
//!
//! The `slots_mac` is an HMAC over the 32-byte `slots_hash` (the SHA-256 of
//! the slots transcript, which binds the header fields, the shuffled slot set,
//! and the item's `hashes_hash`), keyed by an HKDF expansion of the CEK. The
//! content carries no per-chunk AAD: it is bound to the header transitively,
//! because `payload_key` derives from the CEK and the CEK is committed by
//! `slots_mac`.
//!
//! Randomness for the anonymity shuffle, and for any absent CEK / nonce /
//! ephemeral material, comes from a caller-supplied [`RandomSource`] closure —
//! never from a hidden global RNG. This keeps the crate free of a runtime
//! random-number dependency and makes every wrap reproducible: the host (which
//! owns its CSPRNG) passes one in, while the cross-implementation vectors pass
//! every secret explicitly and disable the shuffle, so the closure is never
//! consulted on the deterministic path.

use std::collections::BTreeMap;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::kdf::hkdf_sha256;

use super::aead::chacha20_poly1305_encrypt;
use super::errors::{EciesSealedPoeError, EciesSealedPoeErrorCode};
use super::kem::{
    mlkem768x25519_encapsulate, x25519_ecdh, x25519_public_key, MLKEM768X25519_ENC_LENGTH,
    MLKEM768X25519_ESEED_LENGTH, MLKEM768X25519_PUBLIC_KEY_LENGTH,
};
use super::slots::{
    Mlkem768X25519Slot, SealedEnvelope, SealedPoeOutput, SealedSlots, X25519Slot,
    AEAD_CHACHA20_POLY1305_STREAM64K, KEM_MLKEM768X25519, KEM_X25519,
};
use super::stream::stream_seal;
use super::transcript::{
    compute_slots_hash, item_hashes_hash, slots_payload_key, x25519_kek_salt, xwing_kek_salt,
};

/// The classical per-slot KEK derivation label, reused verbatim as the per-slot
/// wrap AEAD's associated data. 18 bytes.
pub const CARDANO_POE_HKDF_INFO_KEK: &[u8] = b"cardano-poe-kek-v1";

/// The hybrid (X-Wing) per-slot KEK derivation label, reused verbatim as the
/// per-slot wrap AEAD's associated data. Distinct from the classical label so a
/// KEK derived under one KEM can never collide with the other. 33 bytes.
pub const CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519: &[u8] = b"cardano-poe-kek-mlkem768x25519-v1";

/// The `slots_mac` HMAC-key derivation label. 24 bytes.
pub const CARDANO_POE_HKDF_INFO_SLOTS_MAC: &[u8] = b"cardano-poe-slots-mac-v1";

const _: () = {
    assert!(CARDANO_POE_HKDF_INFO_KEK.len() == 18);
    assert!(CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519.len() == 33);
    assert!(CARDANO_POE_HKDF_INFO_SLOTS_MAC.len() == 24);
};

/// The all-zero 12-byte nonce the per-slot ChaCha20-Poly1305 wrap uses. The
/// KEK is single-use (a fresh ephemeral/encapsulation per slot, salted by the
/// envelope-unique `enc.nonce`), so a fixed nonce is safe.
const ZERO_NONCE_12: [u8; 12] = [0u8; 12];

const X25519_KEY_LENGTH: usize = 32;
const CEK_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 24;
const WRAP_LENGTH: usize = 48;
const SLOTS_MAC_LENGTH: usize = 32;

/// The empty hashes map behind `WrapArgs::default()`. Production callers and
/// vectors always supply the item's real `hashes`.
static EMPTY_HASHES: BTreeMap<String, Vec<u8>> = BTreeMap::new();

/// The KEM branch to seal under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedKem {
    /// Classical age-style ECIES over X25519.
    X25519,
    /// The X-Wing hybrid KEM (ML-KEM-768 + X25519).
    Mlkem768X25519,
}

impl SealedKem {
    /// The on-wire KEM identifier string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            SealedKem::X25519 => KEM_X25519,
            SealedKem::Mlkem768X25519 => KEM_MLKEM768X25519,
        }
    }
}

/// A caller-supplied entropy source: fills the given buffer with random bytes.
///
/// The wrap calls this for the anonymity shuffle and for any absent CEK /
/// nonce / per-recipient ephemeral material.
///
/// # Security
///
/// This closure carries the **entire** confidentiality guarantee of the wrap.
/// It MUST be backed by a cryptographically secure RNG. A weak or no-op closure
/// (one that leaves the buffer zeroed) silently produces an all-zero CEK — a
/// globally known content key — together with a clamped fixed ephemeral key and
/// a fixed nonce, and the wrap still returns `Ok(...)`: total loss of
/// confidentiality with no error. The only legitimate non-CSPRNG use is a
/// known-answer / HSM test that ALSO supplies every secret via the [`WrapArgs`]
/// overrides and sets `skip_shuffle`, in which case the closure is never called.
///
/// Production code should call [`ecies_sealed_poe_wrap_secure`], which sources
/// every secret from the operating-system CSPRNG and removes the chance to wire
/// up the wrong RNG here.
pub type RandomSource<'r> = &'r mut dyn FnMut(&mut [u8]);

/// Inputs to the sealed-PoE wrap ([`ecies_sealed_poe_wrap_secure`] and
/// [`ecies_sealed_poe_wrap_with_rng`]).
///
/// `hashes` is the item's content-hash map (algorithm identifier → digest
/// bytes); its digest is bound into the slots transcript, so the on-chain
/// `slots_mac` commits the envelope to this item's hash claim. `kem` selects
/// the branch (defaulting to classical X25519). `cek`, `nonce`,
/// `ephemeral_secrets`, and `eseeds` are deterministic overrides used to
/// reproduce known-answer vectors; production callers leave them `None` so the
/// supplied [`RandomSource`] draws fresh material. `skip_shuffle` disables the
/// anonymity shuffle, again only for deterministic vectors.
pub struct WrapArgs<'a> {
    /// The plaintext to seal.
    pub plaintext: &'a [u8],
    /// One recipient public key per slot. X25519 keys are 32 bytes; X-Wing keys
    /// are 1216 bytes.
    pub recipient_public_keys: &'a [Vec<u8>],
    /// The item's content-hash map, bound into the slots transcript.
    pub hashes: &'a BTreeMap<String, Vec<u8>>,
    /// The KEM branch. Defaults to [`SealedKem::X25519`] when `None`.
    pub kem: Option<SealedKem>,
    /// Deterministic 32-byte CEK override.
    pub cek: Option<&'a [u8]>,
    /// Deterministic 24-byte nonce override.
    pub nonce: Option<&'a [u8]>,
    /// Deterministic X25519 ephemeral scalars (classical branch only), one per
    /// recipient.
    pub ephemeral_secrets: Option<&'a [Vec<u8>]>,
    /// Deterministic X-Wing encapsulation randomness (64 bytes each, hybrid
    /// branch only), one per recipient.
    pub eseeds: Option<&'a [Vec<u8>]>,
    /// When `true`, skip the anonymity shuffle so slot order is deterministic.
    pub skip_shuffle: bool,
}

impl Default for WrapArgs<'_> {
    fn default() -> Self {
        Self {
            plaintext: &[],
            recipient_public_keys: &[],
            hashes: &EMPTY_HASHES,
            kem: None,
            cek: None,
            nonce: None,
            ephemeral_secrets: None,
            eseeds: None,
            skip_shuffle: false,
        }
    }
}

/// The rejection-sampling ceiling for an unbiased index in `[0, m)`.
///
/// A plain `u32 % m` skews toward low residues whenever `m` does not divide
/// `2^32`. The shuffle's whole purpose is a UNIFORM permutation, so the bias —
/// though negligible — is exactly the property to avoid: any draw at or above
/// this ceiling falls in the final partial block and must be rejected. For a
/// power-of-two `m` the ceiling is `2^32` (nothing is ever rejected).
///
/// # Panics
///
/// Panics if `m` is `0` (an empty range has no valid index).
#[must_use]
pub fn uniform_index_ceiling(m: u32) -> u64 {
    assert!(m != 0, "uniform_index_ceiling: modulus must be positive");
    let two_pow_32: u64 = 1 << 32;
    two_pow_32 - (two_pow_32 % u64::from(m))
}

/// Draw an unbiased index in `[0, m)` from `fill` via rejection sampling.
///
/// `fill` supplies four random bytes per draw; draws at or above
/// [`uniform_index_ceiling`] are rejected and redrawn.
fn uniform_index_below(fill: &mut dyn FnMut(&mut [u8]), m: u32) -> u32 {
    let limit = uniform_index_ceiling(m);
    loop {
        let mut buf = [0u8; 4];
        fill(&mut buf);
        let x = u64::from(u32::from_le_bytes(buf));
        if x < limit {
            return (x % u64::from(m)) as u32;
        }
    }
}

/// Fisher-Yates shuffle keyed by an unbiased index draw from `fill`.
fn csprng_shuffle<T>(arr: &mut [T], fill: &mut dyn FnMut(&mut [u8])) {
    if arr.len() < 2 {
        return;
    }
    for i in (1..arr.len()).rev() {
        let j = uniform_index_below(fill, (i + 1) as u32) as usize;
        arr.swap(i, j);
    }
}

/// Wrap the CEK for one classical recipient: an age-style ECIES stanza.
fn wrap_slot_x25519(
    pub_r: &[u8],
    priv_eph: Option<&[u8]>,
    cek: &[u8],
    nonce: &[u8],
    slot_idx: usize,
    fill: &mut dyn FnMut(&mut [u8]),
) -> Result<X25519Slot, EciesSealedPoeError> {
    let mut owned_eph = [0u8; X25519_KEY_LENGTH];
    let priv_eph: &[u8] = match priv_eph {
        Some(eph) => {
            if eph.len() != X25519_KEY_LENGTH {
                return Err(EciesSealedPoeError::new(
                    EciesSealedPoeErrorCode::InvalidEphemeralSecretLength,
                    format!(
                        "ephemeral_secrets[{slot_idx}] MUST be exactly {X25519_KEY_LENGTH} bytes, got {}",
                        eph.len()
                    ),
                ));
            }
            eph
        }
        None => {
            fill(&mut owned_eph);
            &owned_eph
        }
    };

    // The KEM functions reject a wrong-length recipient public key; the caller
    // has already validated the recipient length, so any error here is internal.
    let epk =
        x25519_public_key(priv_eph).expect("ephemeral scalar is exactly 32 bytes, validated above");
    let mut shared = x25519_ecdh(priv_eph, pub_r).map_err(|e| {
        EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::KemEpkLengthMismatch,
            format!("recipient_public_keys[{slot_idx}] X25519 ECDH failed: {e}"),
        )
    })?;
    // The labelled-hash salt binds the envelope nonce, the slot's ephemeral,
    // and the recipient public key.
    let salt = x25519_kek_salt(nonce, &epk, pub_r);
    let mut kek = hkdf_sha256(&shared, &salt, CARDANO_POE_HKDF_INFO_KEK, 32)
        .expect("32-byte HKDF output is within the RFC 5869 maximum");
    shared.zeroize();

    let wrap = chacha20_poly1305_encrypt(&kek, &ZERO_NONCE_12, CARDANO_POE_HKDF_INFO_KEK, cek);
    kek.zeroize();
    owned_eph.zeroize();
    debug_assert_eq!(wrap.len(), WRAP_LENGTH);
    Ok(X25519Slot {
        epk: epk.to_vec(),
        wrap,
    })
}

/// Wrap the CEK for one hybrid recipient: X-Wing encapsulation → HKDF → AEAD.
fn wrap_slot_mlkem768x25519(
    pub_r: &[u8],
    eseed: &[u8],
    cek: &[u8],
    nonce: &[u8],
    slot_idx: usize,
) -> Result<Mlkem768X25519Slot, EciesSealedPoeError> {
    let encaps = mlkem768x25519_encapsulate(pub_r, eseed).map_err(|e| {
        EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::KemEpkLengthMismatch,
            format!("recipient_public_keys[{slot_idx}] X-Wing encapsulation failed: {e}"),
        )
    })?;
    debug_assert_eq!(encaps.enc.len(), MLKEM768X25519_ENC_LENGTH);
    // The labelled-hash salt binds the envelope nonce, the slot's own X-Wing
    // ciphertext (a slot-unique value), and the recipient public key — the
    // same three bindings as the classical salt, computed outside the KEM over
    // the slot's wire bytes so it holds X-Wing as a black-box KEM.
    let salt = xwing_kek_salt(nonce, &encaps.enc, pub_r);
    let mut kek = hkdf_sha256(
        &encaps.ss,
        &salt,
        CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519,
        32,
    )
    .expect("32-byte HKDF output is within the RFC 5869 maximum");
    let wrap = chacha20_poly1305_encrypt(
        &kek,
        &ZERO_NONCE_12,
        CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519,
        cek,
    );
    kek.zeroize();
    debug_assert_eq!(wrap.len(), WRAP_LENGTH);
    Ok(Mlkem768X25519Slot {
        kem_ct: encaps.enc.to_vec(),
        wrap,
    })
}

/// Compute the `slots_mac`: an HMAC-SHA256 over the 32-byte `slots_hash`, keyed
/// by an HKDF expansion of the CEK.
///
/// `hmac_key = HKDF-SHA256(ikm = CEK, salt = "", info =
/// "cardano-poe-slots-mac-v1")`; `slots_mac = HMAC-SHA256(hmac_key,
/// slots_hash)`. The transcript is pre-hashed to `slots_hash` (header fields +
/// the shuffled slot set + the item's `hashes_hash`); pre-hashing only changes
/// the HMAC message from the full transcript to its SHA-256, leaving the
/// CEK-keyed commitment intact.
fn compute_slots_mac(cek: &[u8], slots_hash: &[u8]) -> [u8; SLOTS_MAC_LENGTH] {
    let mut hmac_key = hkdf_sha256(cek, &[], CARDANO_POE_HKDF_INFO_SLOTS_MAC, 32)
        .expect("32-byte HKDF output is within the RFC 5869 maximum");
    let mut mac =
        <Hmac<Sha256>>::new_from_slice(&hmac_key).expect("HMAC accepts a key of any length");
    mac.update(slots_hash);
    let out: [u8; SLOTS_MAC_LENGTH] = mac.finalize().into_bytes().into();
    hmac_key.zeroize();
    out
}

/// Per-slot KEK-uniqueness gate. The zero-nonce per-slot wrap is sound only when
/// every slot's KEK is unique; the KEK is a deterministic function of the slot's
/// KEM material (the x25519 `epk` and recipient public key, or the hybrid
/// `kem_ct` and recipient public key), so two slots carrying identical KEM
/// material against the same recipient repeat the (KEK, nonce) pair. Reject an
/// envelope with duplicate per-slot KEM material — a duplicate `epk` for
/// x25519, a duplicate `kem_ct` for the hybrid path — at the producer before
/// committing anything to the wire.
fn assert_unique_slot_kem_material(slots: &SealedSlots) -> Result<(), EciesSealedPoeError> {
    let mut seen: std::collections::HashSet<&[u8]> = std::collections::HashSet::new();
    let (materials, field): (Vec<&[u8]>, &str) = match slots {
        SealedSlots::X25519(slots) => (slots.iter().map(|s| s.epk.as_slice()).collect(), "epk"),
        SealedSlots::Mlkem768X25519(slots) => (
            slots.iter().map(|s| s.kem_ct.as_slice()).collect(),
            "kem_ct",
        ),
    };
    for (i, material) in materials.into_iter().enumerate() {
        if !seen.insert(material) {
            return Err(EciesSealedPoeError::new(
                EciesSealedPoeErrorCode::EncSlotsDuplicateKemMaterial,
                format!(
                    "slots[{i}].{field} duplicates an earlier slot; per-slot KEK uniqueness is violated"
                ),
            ));
        }
    }
    Ok(())
}

/// Seal `plaintext` to one or more recipients, drawing every secret from the
/// operating-system CSPRNG. **This is the primary wrap API.**
///
/// Produces the sealed envelope (header material destined for the on-chain
/// metadata) and the segmented-STREAM content ciphertext (destined for
/// off-chain storage). The CEK encrypts the plaintext once; it is then wrapped
/// per recipient.
///
/// The CEK, nonce, per-recipient ephemeral material, and the anonymity
/// shuffle are all sourced from [`getrandom`] (the OS CSPRNG). Because the
/// entropy source is fixed here, there is no way to accidentally wire up a weak
/// RNG; a host that needs deterministic material for a known-answer or HSM test
/// uses [`ecies_sealed_poe_wrap_with_rng`] with the [`WrapArgs`] overrides
/// instead.
///
/// # Errors
///
/// Returns [`EciesSealedPoeErrorCode::RngUnavailable`] if the OS RNG cannot be
/// read (the wrap fails loudly rather than emitting a zeroed content key), and
/// every error [`ecies_sealed_poe_wrap_with_rng`] can return: an empty recipient
/// list, a recipient public key of the wrong length for the chosen KEM, or a
/// wrong-length / wrong-count deterministic override.
pub fn ecies_sealed_poe_wrap_secure(
    args: WrapArgs<'_>,
) -> Result<SealedPoeOutput, EciesSealedPoeError> {
    // Track an OS-RNG failure out of the `FnMut` (which cannot itself return a
    // Result) and surface it as a typed error afterward. On any failure the
    // buffer is left untouched, but we never proceed to encrypt: the flag is
    // checked before the result is returned.
    let mut rng_error: Option<EciesSealedPoeError> = None;
    let mut fill = |buf: &mut [u8]| {
        if rng_error.is_some() {
            return;
        }
        if let Err(e) = getrandom::getrandom(buf) {
            rng_error = Some(EciesSealedPoeError::new(
                EciesSealedPoeErrorCode::RngUnavailable,
                format!("operating-system CSPRNG is unavailable: {e}"),
            ));
        }
    };
    let result = ecies_sealed_poe_wrap_with_rng(args, &mut fill);
    if let Some(e) = rng_error {
        return Err(e);
    }
    result
}

/// Seal `plaintext` to one or more recipients using a **caller-supplied** RNG.
///
/// This is the deterministic / injected-entropy variant of
/// [`ecies_sealed_poe_wrap_secure`], kept for known-answer-test, HSM, and other
/// reproducible flows. The CEK encrypts the plaintext once; it is then wrapped
/// per recipient. With no [`WrapArgs`] overrides every output is randomised from
/// `rng`; the deterministic overrides reproduce the cross-implementation
/// vectors.
///
/// `rng` supplies entropy for the anonymity shuffle and for any absent CEK /
/// nonce / per-recipient ephemeral material. On the fully-deterministic path
/// (every secret supplied and `skip_shuffle` set) it is never called.
///
/// # Security
///
/// `rng` MUST be a cryptographically secure RNG — it carries the whole
/// confidentiality guarantee. A weak or no-op closure yields a zeroed
/// (globally known) CEK and the wrap still succeeds. See [`RandomSource`].
/// **Unless you are running a KAT/HSM flow that supplies every secret via
/// overrides, call [`ecies_sealed_poe_wrap_secure`] instead.**
///
/// # Errors
///
/// Returns an [`EciesSealedPoeError`] when the recipient list is empty, a
/// recipient public key is the wrong length for the chosen KEM, a deterministic
/// override is the wrong length or count, or a CEK/nonce override is the wrong
/// length.
pub fn ecies_sealed_poe_wrap_with_rng(
    args: WrapArgs<'_>,
    rng: RandomSource<'_>,
) -> Result<SealedPoeOutput, EciesSealedPoeError> {
    let kem = args.kem.unwrap_or(SealedKem::X25519);
    let n = args.recipient_public_keys.len();

    if n < 1 {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::EncSlotsEmpty,
            format!("recipient_public_keys.len()={n} must be >= 1"),
        ));
    }

    let expected_pub_len = match kem {
        SealedKem::X25519 => X25519_KEY_LENGTH,
        SealedKem::Mlkem768X25519 => MLKEM768X25519_PUBLIC_KEY_LENGTH,
    };
    for (i, pub_key) in args.recipient_public_keys.iter().enumerate() {
        if pub_key.len() != expected_pub_len {
            return Err(EciesSealedPoeError::new(
                EciesSealedPoeErrorCode::KemEpkLengthMismatch,
                format!(
                    "recipient_public_keys[{i}] MUST be exactly {expected_pub_len} bytes for kem='{}'",
                    kem.as_str()
                ),
            ));
        }
    }

    // Override gating: ephemeral_secrets only for x25519; eseeds only for
    // hybrid; counts must equal n; eseed length is 64.
    match kem {
        SealedKem::X25519 => {
            if args.eseeds.is_some() {
                return Err(EciesSealedPoeError::new(
                    EciesSealedPoeErrorCode::EphemeralSecretsCountMismatch,
                    "eseeds is an X-Wing override and MUST NOT be supplied for kem='x25519'",
                ));
            }
            if let Some(eph) = args.ephemeral_secrets {
                if eph.len() != n {
                    return Err(EciesSealedPoeError::new(
                        EciesSealedPoeErrorCode::EphemeralSecretsCountMismatch,
                        format!(
                            "ephemeral_secrets.len()={} must match recipient_public_keys.len()={n}",
                            eph.len()
                        ),
                    ));
                }
            }
        }
        SealedKem::Mlkem768X25519 => {
            if args.ephemeral_secrets.is_some() {
                return Err(EciesSealedPoeError::new(
                    EciesSealedPoeErrorCode::EphemeralSecretsCountMismatch,
                    "ephemeral_secrets is an X25519 override and MUST NOT be supplied for kem='mlkem768x25519'",
                ));
            }
            if let Some(eseeds) = args.eseeds {
                if eseeds.len() != n {
                    return Err(EciesSealedPoeError::new(
                        EciesSealedPoeErrorCode::EphemeralSecretsCountMismatch,
                        format!(
                            "eseeds.len()={} must match recipient_public_keys.len()={n}",
                            eseeds.len()
                        ),
                    ));
                }
                for (i, eseed) in eseeds.iter().enumerate() {
                    if eseed.len() != MLKEM768X25519_ESEED_LENGTH {
                        return Err(EciesSealedPoeError::new(
                            EciesSealedPoeErrorCode::InvalidEphemeralSecretLength,
                            format!(
                                "eseeds[{i}] MUST be exactly {MLKEM768X25519_ESEED_LENGTH} bytes, got {}",
                                eseed.len()
                            ),
                        ));
                    }
                }
            }
        }
    }

    // CEK + nonce: explicit override or fresh randomness.
    let mut owned_cek = [0u8; CEK_LENGTH];
    let cek: &[u8] = match args.cek {
        Some(c) => {
            if c.len() != CEK_LENGTH {
                return Err(EciesSealedPoeError::new(
                    EciesSealedPoeErrorCode::InvalidCekLength,
                    format!("cek MUST be exactly {CEK_LENGTH} bytes, got {}", c.len()),
                ));
            }
            c
        }
        None => {
            rng(&mut owned_cek);
            &owned_cek
        }
    };
    let mut owned_nonce = [0u8; NONCE_LENGTH];
    let nonce: &[u8] = match args.nonce {
        Some(nc) => {
            if nc.len() != NONCE_LENGTH {
                return Err(EciesSealedPoeError::new(
                    EciesSealedPoeErrorCode::NonceLengthMismatch,
                    format!(
                        "nonce MUST be exactly {NONCE_LENGTH} bytes, got {}",
                        nc.len()
                    ),
                ));
            }
            nc
        }
        None => {
            rng(&mut owned_nonce);
            &owned_nonce
        }
    };

    let slots = match kem {
        SealedKem::X25519 => {
            let mut slots = Vec::with_capacity(n);
            for (i, pub_r) in args.recipient_public_keys.iter().enumerate() {
                let priv_eph = args.ephemeral_secrets.map(|e| e[i].as_slice());
                slots.push(wrap_slot_x25519(pub_r, priv_eph, cek, nonce, i, rng)?);
            }
            SealedSlots::X25519(slots)
        }
        SealedKem::Mlkem768X25519 => {
            let mut slots = Vec::with_capacity(n);
            for (i, pub_r) in args.recipient_public_keys.iter().enumerate() {
                // An eseed override is required to be deterministic; absent, a
                // fresh 64-byte encapsulation seed is drawn.
                let mut fresh = [0u8; MLKEM768X25519_ESEED_LENGTH];
                let eseed: &[u8] = match args.eseeds {
                    Some(e) => e[i].as_slice(),
                    None => {
                        rng(&mut fresh);
                        &fresh
                    }
                };
                let slot = wrap_slot_mlkem768x25519(pub_r, eseed, cek, nonce, i);
                fresh.zeroize();
                slots.push(slot?);
            }
            SealedSlots::Mlkem768X25519(slots)
        }
    };

    // Per-slot KEK uniqueness is the safety condition for the zero-nonce wrap.
    // Duplicate per-slot KEM material (a repeated x25519 epk, or a repeated
    // hybrid kem_ct) would repeat the (KEK, nonce) pair, so reject it at the
    // producer before committing anything to the wire.
    assert_unique_slot_kem_material(&slots)?;

    // Anonymity invariant: post-wrap CSPRNG shuffle so wire ordering encodes no
    // recipient identity. The transcript (and thus the MAC) is built AFTER the
    // shuffle, binding the on-wire slot order.
    let mut slots = slots;
    if !args.skip_shuffle {
        match &mut slots {
            SealedSlots::X25519(s) => csprng_shuffle(s, rng),
            SealedSlots::Mlkem768X25519(s) => csprng_shuffle(s, rng),
        }
    }

    // `slots_hash` is the SHA-256 of the slots transcript: the header fields,
    // the shuffled slot set, and the digest of the item's hashes map. Computed
    // once here and fed into the slot-set MAC.
    let hashes_hash = item_hashes_hash(args.hashes)?;
    let slots_hash = compute_slots_hash(
        AEAD_CHACHA20_POLY1305_STREAM64K,
        kem.as_str(),
        nonce,
        &slots,
        &hashes_hash,
    );
    let slots_mac = compute_slots_mac(cek, &slots_hash);

    // Content is encrypted under a derived `payload_key` (a separate HKDF leaf
    // of the CEK salted by the envelope-unique nonce), never under the CEK
    // directly, so the wrap layer and the content layer never key the same
    // primitive on the same bytes. The STREAM chunks carry no per-chunk AAD:
    // the header is bound transitively through the CEK commitment.
    let mut payload_key = slots_payload_key(cek, nonce);
    let ciphertext = stream_seal(&payload_key, args.plaintext);

    payload_key.zeroize();
    owned_cek.zeroize();

    Ok(SealedPoeOutput {
        envelope: SealedEnvelope {
            scheme: 1,
            aead: AEAD_CHACHA20_POLY1305_STREAM64K.to_string(),
            kem: kem.as_str().to_string(),
            nonce: nonce.to_vec(),
            slots,
            slots_mac: slots_mac.to_vec(),
        },
        ciphertext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_label_byte_lengths_match_the_protocol() {
        assert_eq!(CARDANO_POE_HKDF_INFO_KEK.len(), 18);
        assert_eq!(CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519.len(), 33);
        assert_eq!(CARDANO_POE_HKDF_INFO_SLOTS_MAC.len(), 24);
    }

    #[test]
    fn uniform_index_ceiling_is_a_multiple_of_m_and_two_pow_32_for_powers_of_two() {
        let two_pow_32: u64 = 1 << 32;
        for m in [2u32, 3, 4, 5, 6, 7, 8, 17, 64, 100, 256, 257, 1000] {
            let limit = uniform_index_ceiling(m);
            assert_eq!(limit % u64::from(m), 0);
            let is_power_of_two = m.is_power_of_two();
            assert_eq!(limit == two_pow_32, is_power_of_two);
        }
    }

    #[test]
    fn uniform_index_below_stays_in_range() {
        // A trivial counter "RNG" suffices to exercise the range invariant.
        let mut ctr: u32 = 0;
        let mut fill = |buf: &mut [u8]| {
            ctr = ctr.wrapping_add(0x9e37_79b9);
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (ctr >> (8 * (i % 4))) as u8;
            }
        };
        for m in [1u32, 2, 3, 5, 7, 17, 100, 257] {
            for _ in 0..200 {
                let v = uniform_index_below(&mut fill, m);
                assert!(v < m);
            }
        }
    }

    #[test]
    fn empty_recipients_is_rejected() {
        let mut rng = |_: &mut [u8]| panic!("deterministic path must not draw randomness");
        let err = ecies_sealed_poe_wrap_with_rng(
            WrapArgs {
                plaintext: b"",
                recipient_public_keys: &[],
                ..Default::default()
            },
            &mut rng,
        )
        .unwrap_err();
        assert_eq!(err.code(), "ENC_SLOTS_EMPTY");
    }

    #[test]
    fn secure_wrap_draws_fresh_random_material_each_call() {
        // The secure entry point sources every secret from the OS CSPRNG, so
        // two wraps of the same plaintext to the same recipient differ in CEK,
        // nonce, and ephemeral material — observable as differing ciphertext,
        // nonce, and slot bytes. (A zeroed/weak RNG would make these identical.)
        let recipient = x25519_public_key(&[3u8; X25519_KEY_LENGTH]).unwrap();
        let recipients = vec![recipient.to_vec()];
        let hashes = {
            let mut map = BTreeMap::new();
            map.insert("sha2-256".to_string(), vec![0x11u8; 32]);
            map
        };
        let mk = || {
            ecies_sealed_poe_wrap_secure(WrapArgs {
                plaintext: b"hello sealed poe",
                recipient_public_keys: &recipients,
                hashes: &hashes,
                ..Default::default()
            })
            .unwrap()
        };
        let a = mk();
        let b = mk();
        assert_ne!(a.ciphertext, b.ciphertext, "fresh CEK/nonce per wrap");
        assert_ne!(a.envelope.nonce, b.envelope.nonce, "fresh nonce per wrap");
        assert_ne!(
            a.envelope.slots_mac, b.envelope.slots_mac,
            "slots_mac is keyed by the fresh CEK"
        );
        // Sanity: the envelope is well-formed (24-byte nonce, 32-byte MAC).
        assert_eq!(a.envelope.nonce.len(), NONCE_LENGTH);
        assert_eq!(a.envelope.slots_mac.len(), SLOTS_MAC_LENGTH);
    }
}
