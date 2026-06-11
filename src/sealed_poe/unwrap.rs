//! Multi-recipient sealed-PoE unwrap: age-style trial-decrypt with the
//! slot-set MAC folded into per-slot acceptance, constant-time-across-slots
//! scanning, and partitioning-oracle length pre-checks.
//!
//! A slot is accepted only when `kem_ok AND wrap_open_ok AND mac_ok` — the KEM
//! validity bit, the wrap-open, and the slot-set MAC all fold into one
//! per-slot decision. The fold is load-bearing: a malicious sender can craft a
//! slot that wrap-opens under a recipient's key with an attacker-chosen CEK,
//! but that CEK does not reproduce `slots_mac`, so the forged slot is skipped
//! exactly like a non-matching one and an honest slot later in the array still
//! wins.
//!
//! Three caller forms, with exactly one selection:
//!
//! - **single-priv** ([`UnwrapKeys::Single`]) — the standalone-verifier path;
//!   runs the trial-decrypt loop over the slots once.
//! - **multi-priv** ([`UnwrapKeys::Multi`]) — a rotated identity holding
//!   `[current, …archived]`. The outer loop iterates private keys (newest
//!   first, the caller's ordering); the inner loop iterates slots.
//! - **bundle** ([`UnwrapKeys::Bundle`]) — the whole identity key bundle
//!   (both KEMs' secret lists). The dispatch selects the correct list from the
//!   envelope's `kem`, then runs the identical multi-priv loop.
//!
//! Within one private key's pass the loop enters **every** slot regardless of
//! where a match lands, and the accepted CEK is selected with constant-time
//! operations, so the inner loop's timing does not leak the matched slot
//! index. The outer loop short-circuits on the first private key that accepts
//! a slot — this intentionally leaks "which private key matched" (≈ how many
//! rotations the recipient has performed), a weak, locally-observable ordering
//! signal that is not a key or plaintext oracle.
//!
//! Both KEM branches share this control flow; only the per-slot recovery body
//! differs (X25519 ECDH vs. X-Wing decapsulation).

use std::collections::BTreeMap;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

use crate::kdf::hkdf_sha256;

use super::aead::chacha20_poly1305_decrypt;
use super::errors::{EciesSealedPoeError, EciesSealedPoeErrorCode};
use super::kem::{
    mlkem768x25519_decapsulate, mlkem768x25519_public_key_from_seed, x25519_ecdh_unvalidated,
    x25519_public_key, MLKEM768X25519_ENC_LENGTH,
};
use super::slots::{
    Mlkem768X25519Slot, SealedEnvelope, SealedSlots, X25519Slot, AEAD_CHACHA20_POLY1305_STREAM64K,
    KEM_MLKEM768X25519, KEM_X25519,
};
use super::stream::stream_open;
use super::transcript::{
    compute_slots_hash, item_hashes_hash, slots_payload_key, x25519_kek_salt, xwing_kek_salt,
    MAX_DECODED_ENVELOPE_BYTES, MAX_SLOTS,
};
use super::wrap::{
    CARDANO_POE_HKDF_INFO_KEK, CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519,
    CARDANO_POE_HKDF_INFO_SLOTS_MAC,
};

const ZERO_NONCE_12: [u8; 12] = [0u8; 12];
const X25519_SECRET_KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 24;
const WRAP_LENGTH: usize = 48;
const SLOTS_MAC_LENGTH: usize = 32;
const CEK_LENGTH: usize = 32;

/// Why a sealed-PoE unwrap did not recover the plaintext.
///
/// Internal diagnostics for a trusted local caller. An untrusted caller MUST
/// receive one generic failure shape that does not distinguish these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnwrapFailureReason {
    /// No slot was accepted for any supplied private key and no slot even
    /// wrap-opened — the recipient is not addressed by this envelope.
    WrongRecipientKey,
    /// A slot wrap-opened but no accepted candidate emerged (its CEK did not
    /// reproduce `slots_mac`), or two accepted slots recovered different CEKs:
    /// the authenticated envelope header fails its integrity check.
    TamperedHeader,
    /// A CEK was accepted, but the STREAM content open failed: the off-chain
    /// ciphertext was tampered with.
    TamperedCiphertext,
}

impl UnwrapFailureReason {
    /// The stable wire string for this reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            UnwrapFailureReason::WrongRecipientKey => "WRONG_RECIPIENT_KEY",
            UnwrapFailureReason::TamperedHeader => "TAMPERED_HEADER",
            UnwrapFailureReason::TamperedCiphertext => "TAMPERED_CIPHERTEXT",
        }
    }
}

/// The outcome of [`ecies_sealed_poe_unwrap`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnwrapResult {
    /// The plaintext was recovered.
    Matched {
        /// The recovered plaintext.
        plaintext: Vec<u8>,
    },
    /// No plaintext was recovered; `reason` says why.
    NotMatched {
        /// The failure reason.
        reason: UnwrapFailureReason,
    },
}

impl UnwrapResult {
    /// Whether the unwrap recovered a plaintext.
    #[must_use]
    pub fn matched(&self) -> bool {
        matches!(self, UnwrapResult::Matched { .. })
    }
}

/// A recipient's unified key bundle.
///
/// A read-path consumer holds BOTH the X25519 private-key chain (current plus
/// archived, for the classical KEM and rotation history) AND the X-Wing secret
/// seeds (for the hybrid KEM), without knowing which a given record was sealed
/// under. The dispatch picks the right list from the envelope's `kem`:
///
/// - `x25519` → [`x25519_private_keys`](Self::x25519_private_keys)
/// - `mlkem768x25519` → [`mlkem768x25519_secret_seeds`](Self::mlkem768x25519_secret_seeds)
///
/// Both lists are ordered newest-first (the caller's responsibility — the outer
/// trial-decrypt loop scans them in order). Either list MAY be empty when the
/// recipient holds no key for that KEM; a bundle whose selected list is empty
/// is a clean non-match without touching any KEM primitive.
#[derive(Debug, Clone, Default)]
pub struct RecipientKeyBundle {
    /// X25519 private keys, newest first.
    pub x25519_private_keys: Vec<Vec<u8>>,
    /// X-Wing secret seeds, newest first.
    pub mlkem768x25519_secret_seeds: Vec<Vec<u8>>,
}

/// The recipient-key selection for an unwrap.
///
/// Exactly one of the three forms is supplied. The bundle form resolves to a
/// flat list by dispatching on the envelope's `kem`; from there the loop is
/// identical to the multi-priv form.
pub enum UnwrapKeys<'a> {
    /// A single recipient secret key.
    Single(&'a [u8]),
    /// A flat, KEM-pre-selected list of secret keys (newest first).
    Multi(&'a [Vec<u8>]),
    /// A whole key bundle; the KEM list is dispatched from the envelope.
    Bundle(&'a RecipientKeyBundle),
}

/// Test-only instrumentation for the constant-time-across-slots invariants.
///
/// `inner.count` tracks the inner-loop iterations entered for the current
/// private key; in the multi-priv path it is reset at the start of each outer
/// iteration and, after that key's inner loop completes, appended to
/// `inner.per_priv_counts`. `outer.count` is bumped to `k + 1` at the start of
/// each outer iteration. Production callers never construct one.
#[derive(Debug, Default, Clone)]
pub struct UnwrapProbe {
    /// Per-private-key inner-loop accounting.
    pub inner: SlotsAttempted,
    /// Outer-loop (private-key) accounting.
    pub outer: PrivsAttempted,
}

/// Inner-loop (per-slot) iteration accounting for [`UnwrapProbe`].
#[derive(Debug, Default, Clone)]
pub struct SlotsAttempted {
    /// Slots entered for the current private key.
    pub count: usize,
    /// One entry per private key entered: its final inner-loop count.
    pub per_priv_counts: Vec<usize>,
}

/// Outer-loop (private-key) iteration accounting for [`UnwrapProbe`].
#[derive(Debug, Default, Clone)]
pub struct PrivsAttempted {
    /// The highest outer-loop index entered, as `k + 1`.
    pub count: usize,
}

/// The outcome of [`ecies_sealed_poe_trial_decrypt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrialDecryptResult {
    /// A slot was accepted: its CEK passed the per-slot fold (KEM validity,
    /// wrap-open, and the `slots_mac` check).
    Match {
        /// The index of the first accepted slot.
        slot_idx: usize,
        /// The recovered 32-byte content-encryption key.
        cek: Vec<u8>,
    },
    /// No slot was accepted under any supplied private key — the record is
    /// not addressed to (or not trustworthy for) any of them.
    NoMatch,
}

/// Select the secret-key list a bundle contributes for the envelope's KEM.
fn select_bundle_secrets<'a>(
    envelope: &SealedEnvelope,
    bundle: &'a RecipientKeyBundle,
) -> &'a [Vec<u8>] {
    if envelope.kem == KEM_X25519 {
        &bundle.x25519_private_keys
    } else {
        &bundle.mlkem768x25519_secret_seeds
    }
}

/// Validate every wire length BEFORE any KEM/AEAD primitive runs, so a
/// malformed record cannot probe per-slot failure ordering (a partitioning
/// oracle). Shared by the unwrap and trial-decrypt paths to guarantee
/// byte-identical pre-trial behaviour.
fn assert_envelope_structure(
    envelope: &SealedEnvelope,
    multi_priv_keys: Option<&[Vec<u8>]>,
    single_priv_key: Option<&[u8]>,
) -> Result<(), EciesSealedPoeError> {
    if envelope.scheme != 1 {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::UnsupportedEnvelopeScheme,
            format!(
                "envelope.scheme={} unsupported (expected 1)",
                envelope.scheme
            ),
        ));
    }
    if envelope.aead != AEAD_CHACHA20_POLY1305_STREAM64K {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::UnsupportedAeadAlg,
            format!(
                "envelope.aead={} unsupported (expected '{AEAD_CHACHA20_POLY1305_STREAM64K}')",
                envelope.aead
            ),
        ));
    }
    if envelope.kem != KEM_X25519 && envelope.kem != KEM_MLKEM768X25519 {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::UnsupportedKemAlg,
            format!(
                "envelope.kem={} unsupported (expected '{KEM_X25519}' or '{KEM_MLKEM768X25519}')",
                envelope.kem
            ),
        ));
    }

    let n = envelope.slots.len();
    if n < 1 {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::EncSlotsEmpty,
            format!("envelope.slots.len()={n} must be >= 1"),
        ));
    }
    // Resource bound: reject an envelope with more than MAX_SLOTS slots before any
    // KEM/AEAD primitive runs, so a malformed record cannot drive unbounded
    // per-slot work. Checked before the per-slot length loop below.
    if n > MAX_SLOTS {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::EncSlotsTooMany,
            format!("envelope.slots.len()={n} exceeds MAX_SLOTS={MAX_SLOTS}"),
        ));
    }
    if envelope.nonce.len() != NONCE_LENGTH {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::NonceLengthMismatch,
            format!(
                "envelope.nonce MUST be exactly {NONCE_LENGTH} bytes, got {}",
                envelope.nonce.len()
            ),
        ));
    }
    if envelope.slots_mac.len() != SLOTS_MAC_LENGTH {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::EncSlotsMacInvalidLength,
            format!(
                "envelope.slots_mac MUST be exactly {SLOTS_MAC_LENGTH} bytes, got {}",
                envelope.slots_mac.len()
            ),
        ));
    }

    // Per-slot length pre-checks — KEM-driven. ALL slots are validated here,
    // before any decapsulation, so the trial-decrypt loop never observes a
    // malformed slot (partitioning-oracle-safe ordering). The envelope's `kem`
    // string is validated above; the slot variant always matches the chosen KEM
    // because it can only be built that way (parsing routes on the same `kem`).
    //
    // Per-slot KEK uniqueness is also enforced here. The zero-nonce per-slot
    // wrap is safe only because each slot draws fresh KEM randomness, so its KEK
    // is unique; two slots sharing the same KEM material derive the same KEK and
    // repeat a (KEK, zero-nonce) pair. The KEM material that fixes the KEK is the
    // `epk` (x25519) or the `kem_ct` (hybrid) — both bound into the KEK salt —
    // so a repeat of either across slots is rejected outright.
    let mut seen_kem_material: std::collections::HashSet<&[u8]> = std::collections::HashSet::new();
    match &envelope.slots {
        SealedSlots::X25519(slots) => {
            for (i, slot) in slots.iter().enumerate() {
                if slot.epk.len() != X25519_SECRET_KEY_LENGTH {
                    return Err(EciesSealedPoeError::new(
                        EciesSealedPoeErrorCode::KemEpkLengthMismatch,
                        format!(
                            "envelope.slots[{i}].epk MUST be exactly {X25519_SECRET_KEY_LENGTH} bytes, got {}",
                            slot.epk.len()
                        ),
                    ));
                }
                if slot.wrap.len() != WRAP_LENGTH {
                    return Err(wrap_length_error(i, slot.wrap.len()));
                }
                if !seen_kem_material.insert(&slot.epk) {
                    return Err(duplicate_kem_material_error(i, "epk"));
                }
            }
        }
        SealedSlots::Mlkem768X25519(slots) => {
            for (i, slot) in slots.iter().enumerate() {
                if slot.kem_ct.len() != MLKEM768X25519_ENC_LENGTH {
                    return Err(EciesSealedPoeError::new(
                        EciesSealedPoeErrorCode::KemCtLengthMismatch,
                        format!(
                            "envelope.slots[{i}].kem_ct MUST be exactly {MLKEM768X25519_ENC_LENGTH} bytes, got {}",
                            slot.kem_ct.len()
                        ),
                    ));
                }
                if slot.wrap.len() != WRAP_LENGTH {
                    return Err(wrap_length_error(i, slot.wrap.len()));
                }
                if !seen_kem_material.insert(&slot.kem_ct) {
                    return Err(duplicate_kem_material_error(i, "kem_ct"));
                }
            }
        }
    }

    // Decoded-envelope byte backstop. Every per-slot field above is validated to
    // a fixed length, so the decoded envelope's aggregate size is determined here:
    // nonce + slots_mac + per-slot (epk|kem_ct + wrap). Reject before any KEM/AEAD
    // primitive when it exceeds the bound — a tighter resource cap than MAX_SLOTS
    // for honest records, and the bound a parser that can see the decoded size
    // enforces.
    let per_slot_bytes = match &envelope.slots {
        SealedSlots::X25519(_) => X25519_SECRET_KEY_LENGTH + WRAP_LENGTH,
        SealedSlots::Mlkem768X25519(_) => MLKEM768X25519_ENC_LENGTH + WRAP_LENGTH,
    };
    let decoded_envelope_bytes = NONCE_LENGTH + SLOTS_MAC_LENGTH + n * per_slot_bytes;
    if decoded_envelope_bytes > MAX_DECODED_ENVELOPE_BYTES {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::EncEnvelopeTooLarge,
            format!(
                "decoded envelope size {decoded_envelope_bytes} exceeds MAX_DECODED_ENVELOPE_BYTES={MAX_DECODED_ENVELOPE_BYTES}"
            ),
        ));
    }

    if let Some(keys) = multi_priv_keys {
        for (i, key) in keys.iter().enumerate() {
            if key.len() != X25519_SECRET_KEY_LENGTH {
                return Err(EciesSealedPoeError::new(
                    EciesSealedPoeErrorCode::InvalidRecipientKey,
                    format!(
                        "recipient_secret_keys[{i}] MUST be exactly {X25519_SECRET_KEY_LENGTH} bytes, got {}",
                        key.len()
                    ),
                ));
            }
        }
    } else if let Some(key) = single_priv_key {
        if key.len() != X25519_SECRET_KEY_LENGTH {
            return Err(EciesSealedPoeError::new(
                EciesSealedPoeErrorCode::InvalidRecipientKey,
                format!(
                    "recipient_secret_key MUST be exactly {X25519_SECRET_KEY_LENGTH} bytes, got {}",
                    key.len()
                ),
            ));
        }
    }

    Ok(())
}

fn wrap_length_error(slot_idx: usize, got: usize) -> EciesSealedPoeError {
    EciesSealedPoeError::new(
        EciesSealedPoeErrorCode::WrapLengthMismatch,
        format!("envelope.slots[{slot_idx}].wrap MUST be exactly {WRAP_LENGTH} bytes, got {got}"),
    )
}

fn duplicate_kem_material_error(slot_idx: usize, field: &str) -> EciesSealedPoeError {
    EciesSealedPoeError::new(
        EciesSealedPoeErrorCode::EncSlotsDuplicateKemMaterial,
        format!(
            "envelope.slots[{slot_idx}].{field} duplicates an earlier slot; per-slot KEK uniqueness is violated"
        ),
    )
}

/// Constant-time select between two 32-byte values: returns `a` when `choice`
/// is 1, `b` when 0, with no data-dependent branch.
fn ct_select_32(choice: Choice, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::conditional_select(&b[i], &a[i], choice);
    }
    out
}

/// Open the per-slot wrap, or yield a dummy candidate. Atomic: on AEAD tag
/// failure no plaintext escapes and the returned candidate is the fixed
/// all-zero dummy, independent of the failed ciphertext — the caller's MAC
/// step runs over the dummy so the per-slot work stays uniform, and the
/// returned `open_ok` bit forces the fold to reject the slot.
fn wrap_open_or_dummy(kek: &[u8], ad: &[u8], wrap: &[u8]) -> (Choice, [u8; CEK_LENGTH]) {
    match chacha20_poly1305_decrypt(kek, &ZERO_NONCE_12, ad, wrap) {
        Ok(mut plaintext) => {
            // The wrap is pre-validated to 48 bytes, so the recovered CEK is
            // exactly 32; anything else is treated as a failed open.
            if plaintext.len() == CEK_LENGTH {
                let mut cek = [0u8; CEK_LENGTH];
                cek.copy_from_slice(&plaintext);
                plaintext.zeroize();
                (Choice::from(1), cek)
            } else {
                plaintext.zeroize();
                (Choice::from(0), [0u8; CEK_LENGTH])
            }
        }
        Err(_) => (Choice::from(0), [0u8; CEK_LENGTH]),
    }
}

/// Classical (x25519) per-slot KEK + wrap-open. Returns the combined
/// `kem_ok AND open_ok` bit and the candidate CEK (the all-zero dummy when the
/// bit is 0).
///
/// `x25519-dalek` does NOT reject a small-order epk — it returns the all-zero
/// shared secret — so this takes the full ct-select shape: it derives
/// `real_KEK` from the (possibly all-zero) shared secret and a `dummy_KEK`
/// from `0^32`, constant-time-selects the KEK on the secret-independent
/// validity bit, and folds that bit into the result. An invalid-ECDH slot thus
/// uses the dummy KEK and can never be accepted regardless of the AEAD tag,
/// while paying the exact same per-slot work.
fn x25519_slot_candidate(
    slot: &X25519Slot,
    recipient_secret_key: &[u8],
    pub_r_local: &[u8],
    nonce: &[u8],
) -> (Choice, [u8; CEK_LENGTH]) {
    // Non-rejecting ECDH: raw shared secret plus the constant-time validity
    // bit. Key and epk lengths are guaranteed valid upstream, so a length
    // error is unreachable.
    let (mut shared, kem_ok) = x25519_ecdh_unvalidated(recipient_secret_key, &slot.epk)
        .expect("recipient key and epk lengths are pre-validated");
    let salt = x25519_kek_salt(nonce, &slot.epk, pub_r_local);
    // Both KEKs are derived unconditionally so the work is identical whether or
    // not the slot is valid; the KEK actually used is selected in constant time.
    let mut real_kek: [u8; 32] = hkdf_sha256(&shared, &salt, CARDANO_POE_HKDF_INFO_KEK, 32)
        .expect("32-byte HKDF output is within the RFC 5869 maximum")
        .try_into()
        .expect("HKDF returned the requested 32 bytes");
    shared.zeroize();
    let mut dummy_kek: [u8; 32] = hkdf_sha256(&[0u8; 32], &salt, CARDANO_POE_HKDF_INFO_KEK, 32)
        .expect("32-byte HKDF output is within the RFC 5869 maximum")
        .try_into()
        .expect("HKDF returned the requested 32 bytes");
    let mut kek = ct_select_32(kem_ok, &real_kek, &dummy_kek);
    real_kek.zeroize();
    dummy_kek.zeroize();

    let (open_ok, candidate) = wrap_open_or_dummy(&kek, CARDANO_POE_HKDF_INFO_KEK, &slot.wrap);
    kek.zeroize();
    (kem_ok & open_ok, candidate)
}

/// Hybrid (mlkem768x25519) per-slot KEK + wrap-open. X-Wing decapsulation
/// never throws on attacker wire data (ML-KEM implicit rejection), so a wrong
/// shared secret simply yields a KEK that fails the AEAD tag; the KEM validity
/// bit is constant 1 and acceptance rides on the wrap-open and MAC fold.
///
/// `pub_r` is the recipient's own 1216-byte X-Wing public key, recomputed once
/// from the held seed — the same value the producer bound into the KEK salt.
fn mlkem768x25519_slot_candidate(
    slot: &Mlkem768X25519Slot,
    recipient_secret_seed: &[u8],
    pub_r: &[u8],
    nonce: &[u8],
) -> (Choice, [u8; CEK_LENGTH]) {
    // kem_ct length and seed length are validated upstream, so decapsulation
    // is constant-work and cannot fail.
    let mut ss = mlkem768x25519_decapsulate(recipient_secret_seed, &slot.kem_ct)
        .expect("kem_ct and seed lengths are pre-validated");
    let salt = xwing_kek_salt(nonce, &slot.kem_ct, pub_r);
    let mut kek = hkdf_sha256(&ss, &salt, CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519, 32)
        .expect("32-byte HKDF output is within the RFC 5869 maximum");
    ss.zeroize();
    let (open_ok, candidate) =
        wrap_open_or_dummy(&kek, CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519, &slot.wrap);
    kek.zeroize();
    (open_ok, candidate)
}

/// One private key's pass over every slot, with the slot-set MAC folded into
/// per-slot acceptance.
struct InnerScan {
    /// Whether any slot was accepted (`kem_ok AND open_ok AND mac_ok`).
    found: bool,
    /// Whether a later accepted slot recovered a CEK that differs from the
    /// selected one — a slot-set commitment collision; the caller fails closed.
    cek_conflict: bool,
    /// Whether any slot at least wrap-opened (`kem_ok AND open_ok`), accepted
    /// or not. Distinguishes a tampered slot set from a non-recipient key.
    any_wrap_opened: bool,
    /// The first accepted slot's CEK (all-zero when `found` is false).
    selected_cek: [u8; CEK_LENGTH],
    /// The first accepted slot's index (0 when `found` is false).
    selected_idx: usize,
}

/// Run the per-slot fold for one private key. Every slot is entered — no early
/// exit — and the running state (`found`, `cek_conflict`, the selected CEK and
/// index) is folded with constant-time operations:
///
/// ```text
/// ok           = kem_ok AND open_ok AND mac_ok
/// first        = ok AND NOT found
/// cek_conflict = cek_conflict OR (ok AND found AND NOT ct_eq(candidate, selected))
/// selected_CEK = ct_select(first, candidate, selected)
/// found        = found OR ok
/// ```
///
/// The MAC check re-keys HMAC from each candidate CEK (the dummy on a failed
/// open, so the per-slot work is uniform) over the same precomputed 32-byte
/// `slots_hash`.
fn scan_slots_for_key(
    envelope: &SealedEnvelope,
    recipient_secret_key: &[u8],
    slots_hash: &[u8; 32],
    probe: Option<&mut SlotsAttempted>,
) -> InnerScan {
    let mut found = Choice::from(0);
    let mut cek_conflict = Choice::from(0);
    let mut any_wrap_opened = Choice::from(0);
    let mut selected_cek = [0u8; CEK_LENGTH];
    let mut selected_idx = 0u32;
    let mut slots_entered = 0usize;

    let mut fold = |i: usize, open_bit: Choice, candidate: &mut [u8; CEK_LENGTH]| {
        let mac_ok = slots_mac_bit(candidate, slots_hash, &envelope.slots_mac);
        let ok = open_bit & mac_ok;
        let first = ok & !found;
        cek_conflict |= ok & found & !candidate.ct_eq(&selected_cek);
        selected_cek = ct_select_32(first, candidate, &selected_cek);
        selected_idx.conditional_assign(&(i as u32), first);
        found |= ok;
        any_wrap_opened |= open_bit;
        candidate.zeroize();
    };

    match &envelope.slots {
        SealedSlots::X25519(slots) => {
            let pub_r_local =
                x25519_public_key(recipient_secret_key).expect("recipient key length checked");
            for (i, slot) in slots.iter().enumerate() {
                slots_entered = i + 1;
                let (open_bit, mut candidate) = x25519_slot_candidate(
                    slot,
                    recipient_secret_key,
                    &pub_r_local,
                    &envelope.nonce,
                );
                fold(i, open_bit, &mut candidate);
            }
        }
        SealedSlots::Mlkem768X25519(slots) => {
            // Recompute the recipient's own X-Wing public key from the held
            // seed: the hybrid KEK salt binds `pub_R`, so each private key in
            // a multi-key scan MUST re-derive it (a single shared pub_R would
            // compute the wrong KEK for every key but one).
            let pub_r = mlkem768x25519_public_key_from_seed(recipient_secret_key)
                .expect("recipient seed length checked");
            for (i, slot) in slots.iter().enumerate() {
                slots_entered = i + 1;
                let (open_bit, mut candidate) = mlkem768x25519_slot_candidate(
                    slot,
                    recipient_secret_key,
                    &pub_r,
                    &envelope.nonce,
                );
                fold(i, open_bit, &mut candidate);
            }
        }
    }

    if let Some(p) = probe {
        p.count = slots_entered;
    }
    InnerScan {
        found: found.into(),
        cek_conflict: cek_conflict.into(),
        any_wrap_opened: any_wrap_opened.into(),
        selected_cek,
        selected_idx: selected_idx as usize,
    }
}

/// Recompute the `slots_mac` HMAC for a candidate CEK over the 32-byte
/// `slots_hash` and compare it as a constant-time bit.
fn slots_mac_bit(cek: &[u8], slots_hash: &[u8; 32], expected: &[u8]) -> Choice {
    let mut hmac_key = hkdf_sha256(cek, &[], CARDANO_POE_HKDF_INFO_SLOTS_MAC, 32)
        .expect("32-byte HKDF output is within the RFC 5869 maximum");
    let mut mac =
        <Hmac<Sha256>>::new_from_slice(&hmac_key).expect("HMAC accepts a key of any length");
    mac.update(slots_hash);
    let calc = mac.finalize().into_bytes();
    hmac_key.zeroize();
    calc.ct_eq(expected)
}

/// The outcome of the shared key loop: an accepted CEK or a typed reason.
enum KeyLoopOutcome {
    Accepted { cek: [u8; CEK_LENGTH] },
    NotMatched(UnwrapFailureReason),
}

/// Run the trial-decrypt over a list of private keys (the multi-priv outer
/// loop; a single key is the one-element case). The loop short-circuits across
/// keys on the first acceptance — the documented weak cross-key timing
/// trade-off — but stays constant-time across the slots of any single key.
///
/// A per-key CEK conflict (two accepted slots recovering different CEKs) fails
/// the record closed immediately: the slot set is anomalous regardless of
/// which key observed it.
fn scan_keys(
    envelope: &SealedEnvelope,
    keys: &[Vec<u8>],
    slots_hash: &[u8; 32],
    mut probe: Option<&mut UnwrapProbe>,
) -> KeyLoopOutcome {
    let mut any_wrap_opened = false;
    for (k, key) in keys.iter().enumerate() {
        if let Some(p) = probe.as_deref_mut() {
            p.outer.count = k + 1;
        }
        let mut slots_attempted = SlotsAttempted::default();
        let scan = scan_slots_for_key(envelope, key, slots_hash, Some(&mut slots_attempted));
        if let Some(p) = probe.as_deref_mut() {
            p.inner.count = slots_attempted.count;
            p.inner.per_priv_counts.push(slots_attempted.count);
        }
        if scan.cek_conflict {
            return KeyLoopOutcome::NotMatched(UnwrapFailureReason::TamperedHeader);
        }
        if scan.found {
            return KeyLoopOutcome::Accepted {
                cek: scan.selected_cek,
            };
        }
        any_wrap_opened = any_wrap_opened || scan.any_wrap_opened;
    }
    // No key accepted a slot. A slot that wrap-opened without reproducing
    // `slots_mac` indicts the slot set; nothing opening at all means the key
    // is simply not a recipient.
    KeyLoopOutcome::NotMatched(if any_wrap_opened {
        UnwrapFailureReason::TamperedHeader
    } else {
        UnwrapFailureReason::WrongRecipientKey
    })
}

/// Recover the plaintext from a sealed envelope and its content ciphertext.
///
/// `hashes` is the item's content-hash map: its digest is bound into the slots
/// transcript, so the on-chain `slots_mac` only verifies for the hash claim
/// the envelope was sealed for — a spliced envelope fails here, before any
/// content work. Trial-decrypts every slot under the supplied key(s) with the
/// per-slot acceptance fold, then opens the segmented-STREAM content under a
/// CEK-derived `payload_key`. Returns [`UnwrapResult::Matched`] with the
/// plaintext, or [`UnwrapResult::NotMatched`] with the failure reason — a
/// wrong recipient key, a tampered header, or a tampered ciphertext are all
/// structured results, never errors.
///
/// # Errors
///
/// Returns an [`EciesSealedPoeError`] only for malformed input: an unsupported
/// algorithm, a wrong-length wire field (partitioning-oracle pre-check), a
/// wrong-length recipient key, or an empty flat multi-priv list.
pub fn ecies_sealed_poe_unwrap(
    envelope: &SealedEnvelope,
    ciphertext: &[u8],
    hashes: &BTreeMap<String, Vec<u8>>,
    keys: UnwrapKeys<'_>,
    mut probe: Option<&mut UnwrapProbe>,
) -> Result<UnwrapResult, EciesSealedPoeError> {
    // Resolve the caller form to either a single key or a flat multi-priv list.
    // `is_bundle` distinguishes an empty bundle (a clean non-match) from an
    // empty flat list (a programmer error).
    let mut single: Option<&[u8]> = None;
    let mut multi: Option<&[Vec<u8>]> = None;
    let mut is_bundle = false;
    match keys {
        UnwrapKeys::Single(k) => single = Some(k),
        UnwrapKeys::Multi(list) => multi = Some(list),
        UnwrapKeys::Bundle(bundle) => {
            multi = Some(select_bundle_secrets(envelope, bundle));
            is_bundle = true;
        }
    }

    // A bundle whose selected list is empty is a legitimate non-match (the
    // recipient holds no key of the matching kind), not a malformed call. The
    // flat multi-priv form keeps the "empty array is a programmer error"
    // contract its low-level callers rely on.
    if let Some(list) = multi {
        if list.is_empty() {
            if is_bundle {
                return Ok(UnwrapResult::NotMatched {
                    reason: UnwrapFailureReason::WrongRecipientKey,
                });
            }
            return Err(EciesSealedPoeError::new(
                EciesSealedPoeErrorCode::InvalidRecipientKey,
                "recipient_secret_keys MUST be a non-empty list, got length 0",
            ));
        }
    }

    assert_envelope_structure(envelope, multi, single)?;

    // The slots-transcript hash is constant across the whole trial-decrypt —
    // compute it ONCE, then re-key the HMAC from each candidate CEK over this
    // same 32-byte message.
    let hashes_hash = item_hashes_hash(hashes)?;
    let slots_hash = compute_slots_hash(
        &envelope.aead,
        &envelope.kem,
        &envelope.nonce,
        &envelope.slots,
        &hashes_hash,
    );

    let outcome = match single {
        Some(key) => {
            // The single-priv form runs the same loop over one key but never
            // touches the multi-priv outer counter.
            let mut slots_attempted = SlotsAttempted::default();
            let scan = scan_slots_for_key(envelope, key, &slots_hash, Some(&mut slots_attempted));
            if let Some(p) = probe.as_deref_mut() {
                p.inner.count = slots_attempted.count;
            }
            if scan.cek_conflict {
                KeyLoopOutcome::NotMatched(UnwrapFailureReason::TamperedHeader)
            } else if scan.found {
                KeyLoopOutcome::Accepted {
                    cek: scan.selected_cek,
                }
            } else {
                KeyLoopOutcome::NotMatched(if scan.any_wrap_opened {
                    UnwrapFailureReason::TamperedHeader
                } else {
                    UnwrapFailureReason::WrongRecipientKey
                })
            }
        }
        None => {
            let keys = multi.expect("exactly one of single/multi is set");
            scan_keys(envelope, keys, &slots_hash, probe)
        }
    };

    let mut cek = match outcome {
        KeyLoopOutcome::NotMatched(reason) => {
            return Ok(UnwrapResult::NotMatched { reason });
        }
        KeyLoopOutcome::Accepted { cek } => cek,
    };

    // Content is opened under the derived `payload_key` in the segmented
    // STREAM format; the chunks carry no AAD — the header is bound through the
    // CEK commitment the accepted slot already verified.
    let mut payload_key = slots_payload_key(&cek, &envelope.nonce);
    cek.zeroize();
    let result = match stream_open(&payload_key, ciphertext) {
        Ok(plaintext) => UnwrapResult::Matched { plaintext },
        Err(_) => UnwrapResult::NotMatched {
            reason: UnwrapFailureReason::TamperedCiphertext,
        },
    };
    payload_key.zeroize();
    Ok(result)
}

/// The recipient-key selection for a trial-decrypt.
///
/// Exactly one form. The bundle form dispatches on the envelope's `kem`; an
/// empty selected bundle list is a clean [`TrialDecryptResult::NoMatch`],
/// while an empty flat list stays a programmer error.
pub enum TrialDecryptKeys<'a> {
    /// A flat, KEM-pre-selected list of secret keys (newest first).
    Multi(&'a [Vec<u8>]),
    /// A whole key bundle; the KEM list is dispatched from the envelope.
    Bundle(&'a RecipientKeyBundle),
}

/// The trial-decrypt half of the unwrap: recover the CEK and slot index without
/// touching the content ciphertext.
///
/// Used by an inbox-scan agent that has the on-chain envelope but fetches the
/// off-chain ciphertext only when the user invokes decrypt. `hashes` is the
/// item's content-hash map, bound into the slots transcript exactly as in
/// [`ecies_sealed_poe_unwrap`]: same partitioning-oracle pre-checks, same
/// per-slot acceptance fold, same constant-time-across-slots invariant, same
/// documented cross-key short-circuit. It differs only in the return shape: a
/// key whose pass observes a CEK conflict contributes no match (the slot set
/// is not trustworthy), and every non-acceptance reduces to
/// [`TrialDecryptResult::NoMatch`].
///
/// # Errors
///
/// Returns an [`EciesSealedPoeError`] for malformed input (unsupported
/// algorithm, wrong-length wire field, wrong-length recipient key, or an empty
/// flat list).
pub fn ecies_sealed_poe_trial_decrypt(
    envelope: &SealedEnvelope,
    hashes: &BTreeMap<String, Vec<u8>>,
    keys: TrialDecryptKeys<'_>,
    mut probe: Option<&mut UnwrapProbe>,
) -> Result<TrialDecryptResult, EciesSealedPoeError> {
    let (recipient_secret_keys, is_bundle): (&[Vec<u8>], bool) = match keys {
        TrialDecryptKeys::Multi(list) => (list, false),
        TrialDecryptKeys::Bundle(bundle) => (select_bundle_secrets(envelope, bundle), true),
    };

    if recipient_secret_keys.is_empty() {
        if is_bundle {
            return Ok(TrialDecryptResult::NoMatch);
        }
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::InvalidRecipientKey,
            "recipient_secret_keys MUST be a non-empty list, got length 0",
        ));
    }

    assert_envelope_structure(envelope, Some(recipient_secret_keys), None)?;

    let hashes_hash = item_hashes_hash(hashes)?;
    let slots_hash = compute_slots_hash(
        &envelope.aead,
        &envelope.kem,
        &envelope.nonce,
        &envelope.slots,
        &hashes_hash,
    );

    for (k, key) in recipient_secret_keys.iter().enumerate() {
        if let Some(p) = probe.as_deref_mut() {
            p.outer.count = k + 1;
        }
        let mut slots_attempted = SlotsAttempted::default();
        let scan = scan_slots_for_key(envelope, key, &slots_hash, Some(&mut slots_attempted));
        if let Some(p) = probe.as_deref_mut() {
            p.inner.count = slots_attempted.count;
            p.inner.per_priv_counts.push(slots_attempted.count);
        }
        // A CEK conflict makes the slot set untrustworthy for this key: never
        // a match, regardless of which slot was accepted first.
        if scan.cek_conflict {
            continue;
        }
        if scan.found {
            return Ok(TrialDecryptResult::Match {
                slot_idx: scan.selected_idx,
                cek: scan.selected_cek.to_vec(),
            });
        }
    }

    Ok(TrialDecryptResult::NoMatch)
}
