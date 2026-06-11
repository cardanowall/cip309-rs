//! Shared, byte-critical pieces of the sealed-PoE construction that the
//! producer (wrap / passphrase seal) and every verifier (unwrap, trial-decrypt,
//! passphrase open) MUST compute byte-for-byte identically:
//!
//! 1. The item-hashes digest `hashes_hash`.
//! 2. The slots transcript, its canonical bytes, and its SHA-256 `slots_hash`.
//! 3. The passphrase transcript, its canonical bytes, and its SHA-256 `pw_hash`.
//! 4. The content `payload_key` derivations from the CEK (both key paths).
//! 5. The per-slot KEK HKDF salts for both KEMs.
//!
//! Keeping these in one module is the interop guarantee: a single divergence in
//! the canonical encoding silently yields a `slots_mac`, a passphrase
//! commitment, or an AEAD tag that another implementation cannot reproduce,
//! with no typed error to localise the fault.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::cbor::{encode_canonical_cbor, CborValue};
use crate::kdf::hkdf_sha256;

use super::errors::{EciesSealedPoeError, EciesSealedPoeErrorCode};
use super::slots::SealedSlots;

/// SHA-256 prefix for the slots-transcript hash `slots_hash`. 31 bytes.
pub const CARDANO_POE_HASH_PREFIX_SLOTS_TRANSCRIPT: &[u8] = b"cardano-poe-slots-transcript-v1";

/// SHA-256 prefix for the passphrase-transcript hash `pw_hash`. 36 bytes.
pub const CARDANO_POE_HASH_PREFIX_PASSPHRASE_TRANSCRIPT: &[u8] =
    b"cardano-poe-passphrase-transcript-v1";

/// SHA-256 prefix for the item-hashes digest `hashes_hash`. 26 bytes.
pub const CARDANO_POE_HASH_PREFIX_ITEM_HASHES: &[u8] = b"cardano-poe-item-hashes-v1";

/// SHA-256 prefix for the classical (x25519) per-slot KEK HKDF salt. 30 bytes.
pub const CARDANO_POE_HASH_PREFIX_X25519_KEK_SALT: &[u8] = b"cardano-poe-x25519-kek-salt-v1";

/// SHA-256 prefix for the hybrid (X-Wing) per-slot KEK HKDF salt. 29 bytes.
pub const CARDANO_POE_HASH_PREFIX_XWING_KEK_SALT: &[u8] = b"cardano-poe-xwing-kek-salt-v1";

/// HKDF info for the slots-path content `payload_key`. 22 bytes.
pub const CARDANO_POE_HKDF_INFO_PAYLOAD: &[u8] = b"cardano-poe-payload-v1";

/// HKDF info for the passphrase-path content `payload_key`. 33 bytes.
pub const CARDANO_POE_HKDF_INFO_PAYLOAD_PASSPHRASE: &[u8] = b"cardano-poe-payload-passphrase-v1";

/// HKDF info for the passphrase commitment MAC key. 29 bytes.
pub const CARDANO_POE_HKDF_INFO_PASSPHRASE_MAC: &[u8] = b"cardano-poe-passphrase-mac-v1";

/// The passphrase normalization profile identifier. A scheme-1-fixed constant
/// fed into the passphrase transcript to pin the exact normalization profile
/// the CEK was derived under; never serialised on the wire.
pub const CARDANO_POE_PW_NORM_PROFILE: &str = "cardano-poe-pw-norm-v1";

// Internal-label byte-length invariants. Each label is exact ASCII with no
// terminator and no length prefix; the assertions keep the constants in sync
// with the literals every conformant verifier hashes against.
const _: () = {
    assert!(CARDANO_POE_HASH_PREFIX_SLOTS_TRANSCRIPT.len() == 31);
    assert!(CARDANO_POE_HASH_PREFIX_PASSPHRASE_TRANSCRIPT.len() == 36);
    assert!(CARDANO_POE_HASH_PREFIX_ITEM_HASHES.len() == 26);
    assert!(CARDANO_POE_HASH_PREFIX_X25519_KEK_SALT.len() == 30);
    assert!(CARDANO_POE_HASH_PREFIX_XWING_KEK_SALT.len() == 29);
    assert!(CARDANO_POE_HKDF_INFO_PAYLOAD.len() == 22);
    assert!(CARDANO_POE_HKDF_INFO_PAYLOAD_PASSPHRASE.len() == 33);
    assert!(CARDANO_POE_HKDF_INFO_PASSPHRASE_MAC.len() == 29);
};

/// Maximum slot count a verifier accepts before invoking any KEM/AEAD primitive.
///
/// A deployment-pinned reference resource bound (not a wire field); deployments
/// MAY tighten it. It sits far above the ~16 KiB Cardano transaction-metadata
/// ceiling that bounds honest records, so a conformant record never trips it.
pub const MAX_SLOTS: usize = 1024;

/// Backstop on the decoded envelope's aggregate byte size (nonce + slots_mac +
/// per-slot wire fields) a verifier enforces before any KEM/AEAD primitive.
///
/// A deployment-pinned reference resource bound, tighter than [`MAX_SLOTS`] for
/// honest records.
pub const MAX_DECODED_ENVELOPE_BYTES: usize = 65536;

/// Labelled SHA-256 over the helper's prefixed input.
fn labelled_sha256(prefix: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// `hashes_hash = SHA-256("cardano-poe-item-hashes-v1" || canonicalEncode(item.hashes))`.
///
/// The digest of the item's complete `hashes` map — every algorithm entry,
/// canonically encoded. Bound into both transcripts, so the on-chain
/// `slots_mac` match (or the in-ciphertext passphrase commitment) confirms the
/// envelope was sealed for **this item's hash claim**: an envelope spliced onto
/// an item with a different `hashes` map fails before any ciphertext work.
///
/// # Errors
///
/// An `enc`-bearing item MUST declare at least one content hash — the
/// ciphertext is bound to the plaintext only through that digest — so an empty
/// map is rejected with `ENC_REQUIRES_CONTENT_HASH`, on both the producer and
/// the verifier side.
pub fn item_hashes_hash(
    hashes: &BTreeMap<String, Vec<u8>>,
) -> Result<[u8; 32], EciesSealedPoeError> {
    if hashes.is_empty() {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::EncRequiresContentHash,
            "hashes MUST carry at least one content-hash entry",
        ));
    }
    let map = CborValue::Map(
        hashes
            .iter()
            .map(|(alg, digest)| {
                (
                    CborValue::text(alg.clone()),
                    CborValue::Bytes(digest.clone()),
                )
            })
            .collect(),
    );
    let encoded = encode_canonical_cbor(&map)
        .expect("a BTreeMap cannot carry duplicate text keys, so encoding cannot fail");
    Ok(labelled_sha256(
        CARDANO_POE_HASH_PREFIX_ITEM_HASHES,
        &[&encoded],
    ))
}

/// The slot array exactly as it appears on the wire, as a [`CborValue`]:
/// `{ epk: bstr, wrap: bstr }` per classical slot, `{ kem_ct: bstr, wrap: bstr }`
/// per hybrid slot. Key order is fixed by the canonical-encode sort.
fn slots_cbor(slots: &SealedSlots) -> CborValue {
    match slots {
        SealedSlots::X25519(slots) => CborValue::Array(
            slots
                .iter()
                .map(|s| {
                    CborValue::Map(vec![
                        (CborValue::text("epk"), CborValue::Bytes(s.epk.clone())),
                        (CborValue::text("wrap"), CborValue::Bytes(s.wrap.clone())),
                    ])
                })
                .collect(),
        ),
        SealedSlots::Mlkem768X25519(slots) => CborValue::Array(
            slots
                .iter()
                .map(|s| {
                    CborValue::Map(vec![
                        (
                            CborValue::text("kem_ct"),
                            CborValue::Bytes(s.kem_ct.clone()),
                        ),
                        (CborValue::text("wrap"), CborValue::Bytes(s.wrap.clone())),
                    ])
                })
                .collect(),
        ),
    }
}

/// `canonicalEncode(SLOTS_TRANSCRIPT)`: the closed seven-key map binding the
/// cross-KEM header fields (`scheme`, `path`, `aead`, `kem`, `nonce`), the
/// shuffled on-wire slot set, and the item's `hashes_hash`.
///
/// The map keys are a SET — their wire order is fixed by the canonical-encode
/// sort (RFC 8949 §4.2.1), never hand-arranged. `aead` carries the envelope's
/// content-format identifier exactly as on the wire.
#[must_use]
pub fn slots_transcript_bytes(
    aead: &str,
    kem: &str,
    nonce: &[u8],
    slots: &SealedSlots,
    hashes_hash: &[u8; 32],
) -> Vec<u8> {
    let transcript = CborValue::Map(vec![
        (CborValue::text("scheme"), CborValue::Unsigned(1)),
        (CborValue::text("path"), CborValue::text("slots")),
        (CborValue::text("aead"), CborValue::text(aead)),
        (CborValue::text("kem"), CborValue::text(kem)),
        (CborValue::text("nonce"), CborValue::Bytes(nonce.to_vec())),
        (CborValue::text("slots"), slots_cbor(slots)),
        (
            CborValue::text("hashes_hash"),
            CborValue::Bytes(hashes_hash.to_vec()),
        ),
    ]);
    encode_canonical_cbor(&transcript)
        .expect("the transcript map has distinct text keys, so encoding cannot fail")
}

/// `slots_hash = SHA-256("cardano-poe-slots-transcript-v1" || canonicalEncode(SLOTS_TRANSCRIPT))`.
///
/// Computed ONCE per envelope and held constant across the recipient
/// trial-decrypt loop: the per-slot MAC check re-keys HMAC from each candidate
/// CEK but always over this same 32-byte message. A relay that flips any header
/// field, slot byte, or the item's hash claim yields a different `slots_hash`
/// and the MAC fails.
#[must_use]
pub fn compute_slots_hash(
    aead: &str,
    kem: &str,
    nonce: &[u8],
    slots: &SealedSlots,
    hashes_hash: &[u8; 32],
) -> [u8; 32] {
    labelled_sha256(
        CARDANO_POE_HASH_PREFIX_SLOTS_TRANSCRIPT,
        &[&slots_transcript_bytes(
            aead,
            kem,
            nonce,
            slots,
            hashes_hash,
        )],
    )
}

/// `canonicalEncode(PASSPHRASE_TRANSCRIPT)`: the closed six-key map binding the
/// passphrase-path header fields, the KDF parameters, the pinned normalization
/// profile, and the item's `hashes_hash`.
///
/// The `normalization` value is the scheme-fixed profile constant — pinned into
/// the transcript, never serialised on the wire.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn passphrase_transcript_bytes(
    aead: &str,
    nonce: &[u8],
    alg: &str,
    salt: &[u8],
    m: u64,
    t: u64,
    p: u64,
    hashes_hash: &[u8; 32],
) -> Vec<u8> {
    let passphrase = CborValue::Map(vec![
        (CborValue::text("alg"), CborValue::text(alg)),
        (CborValue::text("salt"), CborValue::Bytes(salt.to_vec())),
        (
            CborValue::text("params"),
            CborValue::Map(vec![
                (CborValue::text("m"), CborValue::Unsigned(m)),
                (CborValue::text("t"), CborValue::Unsigned(t)),
                (CborValue::text("p"), CborValue::Unsigned(p)),
            ]),
        ),
        (
            CborValue::text("normalization"),
            CborValue::text(CARDANO_POE_PW_NORM_PROFILE),
        ),
    ]);
    let transcript = CborValue::Map(vec![
        (CborValue::text("scheme"), CborValue::Unsigned(1)),
        (CborValue::text("path"), CborValue::text("passphrase")),
        (CborValue::text("aead"), CborValue::text(aead)),
        (CborValue::text("nonce"), CborValue::Bytes(nonce.to_vec())),
        (
            CborValue::text("hashes_hash"),
            CborValue::Bytes(hashes_hash.to_vec()),
        ),
        (CborValue::text("passphrase"), passphrase),
    ]);
    encode_canonical_cbor(&transcript)
        .expect("the transcript map has distinct text keys, so encoding cannot fail")
}

/// `pw_hash = SHA-256("cardano-poe-passphrase-transcript-v1" || canonicalEncode(PASSPHRASE_TRANSCRIPT))`.
///
/// The message of the CEK-keyed passphrase commitment: tampering with `salt`,
/// any `params` value, `nonce`, `aead`, or splicing the envelope onto a
/// different hash claim yields a different `pw_hash`, so the in-ciphertext
/// commitment check fails.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn compute_passphrase_hash(
    aead: &str,
    nonce: &[u8],
    alg: &str,
    salt: &[u8],
    m: u64,
    t: u64,
    p: u64,
    hashes_hash: &[u8; 32],
) -> [u8; 32] {
    labelled_sha256(
        CARDANO_POE_HASH_PREFIX_PASSPHRASE_TRANSCRIPT,
        &[&passphrase_transcript_bytes(
            aead,
            nonce,
            alg,
            salt,
            m,
            t,
            p,
            hashes_hash,
        )],
    )
}

/// Slots-path content key: `HKDF-SHA-256(ikm=CEK, salt=nonce, info=payload-v1)`.
///
/// The content is encrypted under this leaf of the CEK, never under the CEK
/// directly, so the wrap layer and the content layer never key the same
/// primitive on the same bytes. The envelope-unique `nonce` salt makes the
/// key single-use, which is what makes the STREAM counter nonces safe.
#[must_use]
pub fn slots_payload_key(cek: &[u8], nonce: &[u8]) -> Vec<u8> {
    hkdf_sha256(cek, nonce, CARDANO_POE_HKDF_INFO_PAYLOAD, 32)
        .expect("32-byte HKDF output is within the RFC 5869 maximum")
}

/// Passphrase-path content key:
/// `HKDF-SHA-256(ikm=CEK, salt=nonce, info=payload-passphrase-v1)`.
#[must_use]
pub fn passphrase_payload_key(cek: &[u8], nonce: &[u8]) -> Vec<u8> {
    hkdf_sha256(cek, nonce, CARDANO_POE_HKDF_INFO_PAYLOAD_PASSPHRASE, 32)
        .expect("32-byte HKDF output is within the RFC 5869 maximum")
}

/// Classical (x25519) per-slot KEK salt:
/// `SHA-256("cardano-poe-x25519-kek-salt-v1" || enc.nonce || epk || pub_R)`.
///
/// Binds three values: the envelope-unique `enc.nonce` (anchoring the KEK to
/// one envelope, so repeated KEM randomness degrades to linkability instead of
/// a repeated `(KEK, zero-nonce)` wrap pair), the slot's own ephemeral public
/// key (anchoring the KEK to a slot-unique value), and the recipient public
/// key (defeating confused-deputy relay of the ephemeral against a different
/// recipient).
#[must_use]
pub fn x25519_kek_salt(nonce: &[u8], epk: &[u8], pub_r: &[u8]) -> [u8; 32] {
    labelled_sha256(
        CARDANO_POE_HASH_PREFIX_X25519_KEK_SALT,
        &[nonce, epk, pub_r],
    )
}

/// Hybrid (mlkem768x25519) per-slot KEK salt:
/// `SHA-256("cardano-poe-xwing-kek-salt-v1" || enc.nonce || kem_ct || pub_R)`.
///
/// The same three bindings as the classical salt, with the slot's 1120-byte
/// X-Wing ciphertext as the slot-unique value and the 1216-byte X-Wing
/// recipient public key as `pub_R`. Computed outside the KEM, over the slot's
/// own wire bytes, so it holds X-Wing as a black-box KEM.
#[must_use]
pub fn xwing_kek_salt(nonce: &[u8], kem_ct: &[u8], pub_r: &[u8]) -> [u8; 32] {
    labelled_sha256(
        CARDANO_POE_HASH_PREFIX_XWING_KEK_SALT,
        &[nonce, kem_ct, pub_r],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_label_byte_lengths_match_the_protocol() {
        assert_eq!(CARDANO_POE_HASH_PREFIX_SLOTS_TRANSCRIPT.len(), 31);
        assert_eq!(CARDANO_POE_HASH_PREFIX_PASSPHRASE_TRANSCRIPT.len(), 36);
        assert_eq!(CARDANO_POE_HASH_PREFIX_ITEM_HASHES.len(), 26);
        assert_eq!(CARDANO_POE_HASH_PREFIX_X25519_KEK_SALT.len(), 30);
        assert_eq!(CARDANO_POE_HASH_PREFIX_XWING_KEK_SALT.len(), 29);
        assert_eq!(CARDANO_POE_HKDF_INFO_PAYLOAD.len(), 22);
        assert_eq!(CARDANO_POE_HKDF_INFO_PAYLOAD_PASSPHRASE.len(), 33);
        assert_eq!(CARDANO_POE_HKDF_INFO_PASSPHRASE_MAC.len(), 29);
    }

    #[test]
    fn labels_are_pairwise_prefix_free() {
        // No label may equal, or be a byte-prefix of, any other: the input to
        // one labelled hash or HKDF must never reinterpret as another's.
        let labels: [&[u8]; 8] = [
            CARDANO_POE_HASH_PREFIX_SLOTS_TRANSCRIPT,
            CARDANO_POE_HASH_PREFIX_PASSPHRASE_TRANSCRIPT,
            CARDANO_POE_HASH_PREFIX_ITEM_HASHES,
            CARDANO_POE_HASH_PREFIX_X25519_KEK_SALT,
            CARDANO_POE_HASH_PREFIX_XWING_KEK_SALT,
            CARDANO_POE_HKDF_INFO_PAYLOAD,
            CARDANO_POE_HKDF_INFO_PAYLOAD_PASSPHRASE,
            CARDANO_POE_HKDF_INFO_PASSPHRASE_MAC,
        ];
        for (i, a) in labels.iter().enumerate() {
            for (j, b) in labels.iter().enumerate() {
                if i != j {
                    assert!(!b.starts_with(a), "label {i} is a prefix of label {j}");
                }
            }
        }
    }

    #[test]
    fn item_hashes_hash_is_order_independent_and_value_sensitive() {
        let mut a = BTreeMap::new();
        a.insert("sha2-256".to_string(), vec![0x11u8; 32]);
        a.insert("blake2b-256".to_string(), vec![0x22u8; 32]);
        let mut b = BTreeMap::new();
        b.insert("blake2b-256".to_string(), vec![0x22u8; 32]);
        b.insert("sha2-256".to_string(), vec![0x11u8; 32]);
        assert_eq!(item_hashes_hash(&a).unwrap(), item_hashes_hash(&b).unwrap());

        let mut c = a.clone();
        c.insert("sha2-256".to_string(), vec![0x12u8; 32]);
        assert_ne!(item_hashes_hash(&a).unwrap(), item_hashes_hash(&c).unwrap());
    }
}
