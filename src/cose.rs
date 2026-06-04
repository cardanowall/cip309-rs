//! COSE_Sign1 construction and verification (RFC 9052) for Label 309 record
//! signatures, plus the Ed25519 primitive the signatures ride on and the
//! COSE_Key decoder used to resolve out-of-band signer keys.
//!
//! Record-level authorship in Label 309 is expressed by optional `COSE_Sign1`
//! signatures — never required. A signature commits to the canonical-CBOR of the
//! record body (with the `sigs` field removed) under a fixed domain separator,
//! so a verifier can recompute the signed bytes from the record alone. The
//! payload is always detached (CBOR `null`), so the signed bytes live in the
//! record body rather than in the COSE_Sign1 envelope.
//!
//! Everything here is byte-identical to the TypeScript (`@cardanowall/sdk-ts`)
//! and Python (`cardanowall-sdk`) SDKs and is pinned against the shared
//! cross-implementation fixtures.
//!
//! The public surface mirrors the other two SDKs:
//!
//! - [`build_sig_structure`] / [`build_label309_sig_structure`] — the RFC 9052
//!   §4.4 `Sig_structure` and its Label 309 specialisation.
//! - [`encode_cose_sign1`] / [`decode_cose_sign1`] — the untagged 4-element
//!   `COSE_Sign1` wire codec.
//! - [`cose_sign1_label309_build`] — sign a record body, in-process, from a raw
//!   Ed25519 seed or an injected signer closure.
//! - [`cose_sign1_label309_prepare`] / [`cose_sign1_label309_assemble`] — the
//!   off-host split: `prepare` returns the exact bytes an external signer must
//!   Ed25519-sign; `assemble` folds the returned 64-byte signature into the
//!   final `COSE_Sign1`.
//! - [`cose_sign1_label309_verify`] — verify a record signature, including the
//!   CIP-8 hashed-payload mode.
//! - [`parse_cose_key_ed25519`] — decode an OKP/Ed25519 `COSE_Key` to its raw
//!   32-byte public key.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::cbor::{decode_canonical_cbor, encode_canonical_cbor, CanonicalCborError, CborValue};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Label 309 v1 record-signature domain separator.
///
/// This 25-byte UTF-8 string is prepended to the canonical record body to form
/// the signed payload (`to_sign`). It is embedded in the payload rather than in
/// the COSE `external_aad` because the CIP-30 wallet `signData` path — the only
/// realistic wallet-signing route on Cardano — forbids a non-empty
/// `external_aad`. Pinning the separator into the payload keeps wallet-produced
/// signatures byte-identical to verifier-side recomputation while preserving the
/// anti-replay property.
pub const CARDANO_POE_SIG_DOMAIN_PREFIX: &str = "cardano-poe-record-sig-v1";

/// The byte length of the Ed25519 raw public key (and the `kid` header value).
const ED25519_PUBLIC_KEY_LENGTH: usize = 32;

/// The byte length of an Ed25519 signature.
const ED25519_SIGNATURE_LENGTH: usize = 64;

/// COSE header label 1: signature algorithm.
const COSE_HEADER_LABEL_ALG: i64 = 1;

/// COSE header label 4: key identifier.
const COSE_HEADER_LABEL_KID: i64 = 4;

/// COSE algorithm identifier for EdDSA (RFC 9053 §2.2).
const COSE_ALG_EDDSA: i64 = -8;

/// The unprotected-header text key that selects CIP-8 hashed-payload mode.
const HASHED_MODE_HEADER_KEY: &str = "hashed";

// Compile-time guard: the domain prefix is byte-pinned at 25 UTF-8 bytes. A
// different length would silently break round-tripping against the reference
// vectors, so we refuse to compile if it ever drifts.
const _: () = assert!(CARDANO_POE_SIG_DOMAIN_PREFIX.len() == 25);

// ---------------------------------------------------------------------------
// Ed25519 primitive
// ---------------------------------------------------------------------------

/// Ed25519 sign/verify with the exact rule set the Label 309 SDKs require.
///
/// The Rust module map has no standalone signature module; the Ed25519 primitive
/// the COSE layer needs lives here. Verification is **strict** per RFC 8032
/// §5.1.7 (canonical scalar `S < L`, rejection of non-canonical point encodings,
/// rejection of small-order points), matching the `zip215: false` rule the
/// TypeScript and Python twins use. A cofactored verifier would accept
/// signatures this one rejects, so the entry point is fixed to the strict path.
mod ed25519 {
    use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

    /// Derive the 32-byte Ed25519 public key from a 32-byte secret seed.
    pub(super) fn public_key_from_seed(seed: &[u8; 32]) -> [u8; 32] {
        SigningKey::from_bytes(seed).verifying_key().to_bytes()
    }

    /// Ed25519-sign `message` with the 32-byte secret `seed`, returning the
    /// 64-byte signature. Deterministic per RFC 8032 — the same seed and message
    /// always produce the same signature.
    pub(super) fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(seed).sign(message).to_bytes()
    }

    /// Strict Ed25519 verification (RFC 8032 §5.1.7 / `zip215: false`).
    ///
    /// Returns `false` — never an error — for a malformed public key, a
    /// malformed signature, or a signature that does not verify. This is the
    /// boolean surface the COSE verifier expects: a bad signature is a verdict,
    /// not an exception.
    pub(super) fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let pk_bytes: [u8; 32] = match public_key.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig_bytes: [u8; 64] = match signature.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(&pk_bytes) else {
            return false;
        };
        verifying_key
            .verify_strict(message, &Signature::from_bytes(&sig_bytes))
            .is_ok()
    }
}

/// Derive the raw 32-byte Ed25519 public key from a 32-byte secret seed.
///
/// The seed is zeroized from the local copy after use. This is the primitive a
/// signer uses to compute the `kid` it places in the COSE protected header.
///
/// ```
/// use cardanowall::cose::ed25519_public_key_from_seed;
/// // RFC 8032 §7.1 Test 2 seed → public key.
/// let seed = cardanowall::hex::decode(
///     "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
/// )
/// .unwrap();
/// let pk = ed25519_public_key_from_seed(seed.as_slice().try_into().unwrap());
/// assert_eq!(
///     cardanowall::hex::encode(&pk),
///     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
/// );
/// ```
#[must_use]
pub fn ed25519_public_key_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let mut local = *seed;
    let pk = ed25519::public_key_from_seed(&local);
    local.zeroize();
    pk
}

/// Ed25519-sign `message` with a 32-byte secret seed (RFC 8032 deterministic).
///
/// The local copy of the seed is zeroized after signing.
///
/// ```
/// use cardanowall::cose::ed25519_sign;
/// // RFC 8032 §7.1 Test 2.
/// let seed = cardanowall::hex::decode(
///     "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
/// )
/// .unwrap();
/// let sig = ed25519_sign(seed.as_slice().try_into().unwrap(), &[0x72]);
/// assert_eq!(
///     cardanowall::hex::encode(&sig),
///     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
/// );
/// ```
#[must_use]
pub fn ed25519_sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let mut local = *seed;
    let sig = ed25519::sign(&local, message);
    local.zeroize();
    sig
}

/// Strictly verify an Ed25519 signature (RFC 8032 §5.1.7 / `zip215: false`).
///
/// Returns `false` for a malformed key, a malformed signature, or a signature
/// that does not verify under the strict rules — including the small-order
/// public-key and non-canonical-`S` cases a cofactored verifier would wrongly
/// accept.
///
/// ```
/// use cardanowall::cose::ed25519_verify;
/// let pk = cardanowall::hex::decode(
///     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
/// )
/// .unwrap();
/// let sig = cardanowall::hex::decode(
///     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
/// )
/// .unwrap();
/// assert!(ed25519_verify(&pk, &[0x72], &sig));
/// ```
#[must_use]
pub fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    ed25519::verify(public_key, message, signature)
}

// ---------------------------------------------------------------------------
// BLAKE2b-224 (CIP-8 hashed-payload mode)
// ---------------------------------------------------------------------------

/// True 28-byte parameterized BLAKE2b digest of `input`.
///
/// BLAKE2b with the output-length parameter set to 28 (no key, salt, or
/// personalization) per RFC 7693 — **not** a truncation of BLAKE2b-512. CIP-8
/// `hashed = true` mode signs this digest of the full `to_sign` payload.
fn blake2b224(input: &[u8]) -> [u8; 28] {
    use blake2::digest::consts::U28;
    use blake2::digest::Digest;
    use blake2::Blake2b;
    Blake2b::<U28>::digest(input).into()
}

// ---------------------------------------------------------------------------
// COSE header model
// ---------------------------------------------------------------------------

/// A COSE header label: an integer (registered labels) or a text key.
///
/// COSE registers most header parameters under small integers (`1` = alg,
/// `4` = kid), but Label 309's hashed-payload mode is selected by the text key
/// `"hashed"` in the unprotected header. Modelling labels as int-or-text mirrors
/// the `Map<number | string, unknown>` headers of the TypeScript and Python
/// twins exactly, and keeps both kinds encodable as canonical-CBOR map keys.
///
/// The integer label is held as `i128` because a CBOR integer spans
/// `-2^64 ..= 2^64 - 1` — wider than `i64`. A header MAY legally carry an
/// integer label outside the `i64` range (an unknown, very large registered or
/// private-use label); JavaScript and Python decode such a header fine and the
/// `alg` (1) / `kid` (4) lookups only ever consult small labels, so an
/// out-of-range label must be RETAINED and ignored rather than collapsing the
/// whole protected-header decode to a malformed-COSE verdict. `i128` holds the
/// full CBOR integer range losslessly, so no label is ever rejected for its
/// magnitude.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoseLabel {
    /// An integer label (the common COSE case). Held as `i128` so the full CBOR
    /// integer range `-2^64 ..= 2^64 - 1` fits without narrowing loss.
    Int(i128),
    /// A text label (used by Label 309's `"hashed"` flag).
    Text(String),
}

impl CoseLabel {
    /// The canonical-CBOR key form of this label.
    ///
    /// The `i128` integer is mapped back to the CBOR major type it came from:
    /// a non-negative value to [`CborValue::Unsigned`], a negative value to
    /// [`CborValue::Negative`] with argument `-1 - v`. Every value reachable
    /// here originated from a `u64`-backed CBOR integer (the decoder) or a small
    /// `i64` label (the builder), so the round-trip is exact.
    fn to_cbor(&self) -> CborValue {
        match self {
            CoseLabel::Int(v) => cbor_int_from_i128(*v),
            CoseLabel::Text(s) => CborValue::text(s.clone()),
        }
    }
}

/// Encode an `i128` COSE integer label as its CBOR major-type 0/1 value.
///
/// The label range is `-2^64 ..= 2^64 - 1` (the CBOR integer range), which the
/// two `u64`-argument variants represent exactly: a non-negative value is an
/// unsigned integer; a negative value `v` is the negative integer with argument
/// `-1 - v`, computed in `i128` so `v == -2^64` does not overflow.
fn cbor_int_from_i128(v: i128) -> CborValue {
    if v >= 0 {
        CborValue::Unsigned(v as u64)
    } else {
        CborValue::Negative((-1 - v) as u64)
    }
}

/// A COSE header map: ordered `(label, value)` pairs.
///
/// Insertion order is irrelevant to the wire bytes — the canonical-CBOR encoder
/// re-sorts keys by their encoded bytes — but ordered storage keeps the model
/// faithful to the TypeScript/Python `Map` and makes header construction read
/// naturally. An empty protected header serialises to the single byte `0x40`
/// (zero-length byte string); see [`encode_cose_sign1`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CoseHeader {
    pairs: Vec<(CoseLabel, CborValue)>,
}

impl CoseHeader {
    /// An empty header (no parameters).
    #[must_use]
    pub fn new() -> Self {
        Self { pairs: Vec::new() }
    }

    /// `true` if the header carries no parameters.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// The number of parameters in the header.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    /// Set an integer-labelled parameter, replacing any existing value.
    ///
    /// The public surface takes an `i64` because every label this SDK *emits*
    /// (`1` = alg, `4` = kid, and the COSE_Key labels) is small; the value is
    /// widened to the internal `i128` representation that also holds decoded
    /// out-of-range labels.
    #[must_use]
    pub fn with_int(mut self, label: i64, value: CborValue) -> Self {
        self.set(CoseLabel::Int(i128::from(label)), value);
        self
    }

    /// Set a text-labelled parameter, replacing any existing value.
    #[must_use]
    pub fn with_text(mut self, label: impl Into<String>, value: CborValue) -> Self {
        self.set(CoseLabel::Text(label.into()), value);
        self
    }

    /// Insert or replace a parameter by label.
    fn set(&mut self, label: CoseLabel, value: CborValue) {
        if let Some(slot) = self.pairs.iter_mut().find(|(l, _)| *l == label) {
            slot.1 = value;
        } else {
            self.pairs.push((label, value));
        }
    }

    /// Look up an integer-labelled parameter.
    ///
    /// Lookups only ever target small registered labels, so the `i64` argument
    /// is widened to the internal `i128` representation for the comparison; an
    /// out-of-range stored label simply never matches a small lookup key.
    fn get_int(&self, label: i64) -> Option<&CborValue> {
        let label = i128::from(label);
        self.pairs
            .iter()
            .find(|(l, _)| matches!(l, CoseLabel::Int(n) if *n == label))
            .map(|(_, v)| v)
    }

    /// Look up a text-labelled parameter.
    fn get_text(&self, label: &str) -> Option<&CborValue> {
        self.pairs
            .iter()
            .find(|(l, _)| matches!(l, CoseLabel::Text(s) if s == label))
            .map(|(_, v)| v)
    }

    /// The signature algorithm (COSE label 1), if present and an integer.
    ///
    /// Label 309 v1 records carry `alg = -8` (EdDSA) in the protected header.
    #[must_use]
    pub fn alg(&self) -> Option<i64> {
        cbor_int_value(self.get_int(COSE_HEADER_LABEL_ALG))
    }

    /// The 32-byte key identifier (COSE label 4), if present and exactly 32
    /// bytes.
    ///
    /// In Label 309 the `kid` is the raw 32-byte Ed25519 public key, not a hash or
    /// a prefixed identifier. A `kid` of any other length is treated as absent.
    #[must_use]
    pub fn kid(&self) -> Option<[u8; 32]> {
        match self.get_int(COSE_HEADER_LABEL_KID) {
            Some(CborValue::Bytes(b)) if b.len() == ED25519_PUBLIC_KEY_LENGTH => {
                b.as_slice().try_into().ok()
            }
            _ => None,
        }
    }

    /// The canonical-CBOR map form of this header.
    ///
    /// Empty headers encode to the single byte `0xA0` here; the COSE_Sign1
    /// protected slot uses the zero-length byte string `0x40` for an empty
    /// header instead (handled by [`encode_cose_sign1`]).
    #[must_use]
    pub fn to_cbor(&self) -> CborValue {
        CborValue::Map(
            self.pairs
                .iter()
                .map(|(label, value)| (label.to_cbor(), value.clone()))
                .collect(),
        )
    }

    /// Encode this header to its COSE protected-slot bytes.
    ///
    /// An empty header yields an empty vector (carried on the wire as the
    /// zero-length byte string `0x40`); a non-empty header yields its
    /// canonical-CBOR map bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CanonicalCborError`] only if the header carries a duplicate key.
    pub fn encode_protected(&self) -> Result<Vec<u8>, CanonicalCborError> {
        if self.is_empty() {
            Ok(Vec::new())
        } else {
            encode_canonical_cbor(&self.to_cbor())
        }
    }

    /// Build a header from a decoded CBOR map, normalising int/text keys.
    ///
    /// Returns `None` only when the value is not a map or a key is neither an
    /// integer nor a text string (no other key kind appears in a COSE header).
    /// An integer label of *any* magnitude — including one outside the `i64`
    /// range — is retained: the CBOR integer range fits in `i128`, so the
    /// previous narrowing (which rejected the whole header on overflow) is gone.
    /// Retaining a large unknown label is verdict-neutral because the `alg`/`kid`
    /// lookups only consult small labels.
    fn from_cbor_map(value: &CborValue) -> Option<Self> {
        let CborValue::Map(pairs) = value else {
            return None;
        };
        let mut header = CoseHeader::new();
        for (key, val) in pairs {
            let label = match key {
                CborValue::Unsigned(n) => CoseLabel::Int(i128::from(*n)),
                // CBOR negative integer is -1 - m; this never overflows i128
                // (m is at most u64::MAX, so the value bottoms out at -2^64).
                CborValue::Negative(m) => CoseLabel::Int(-1_i128 - i128::from(*m)),
                CborValue::Text(s) => CoseLabel::Text(s.clone()),
                _ => return None,
            };
            header.pairs.push((label, val.clone()));
        }
        Some(header)
    }
}

// ---------------------------------------------------------------------------
// Sig_structure
// ---------------------------------------------------------------------------

/// Build the raw RFC 9052 §4.4 `Sig_structure` and encode it as canonical CBOR.
///
/// This is the general-purpose builder: the caller controls `external_aad` and
/// `payload` exactly. For Label 309 record signing use
/// [`build_label309_sig_structure`], which enforces the v1 invariants
/// (`external_aad = h''` and the 25-byte domain prefix on the payload).
///
/// The structure is the 4-element array
/// `["Signature1", body_protected, external_aad, payload]`. Both
/// `body_protected` and `external_aad` are byte strings; `body_protected` is the
/// COSE_Sign1 protected-header bytes verbatim (never re-encoded).
#[must_use]
pub fn build_sig_structure(
    body_protected_bytes: &[u8],
    external_aad: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let structure = CborValue::Array(vec![
        CborValue::text("Signature1"),
        CborValue::bytes(body_protected_bytes.to_vec()),
        CborValue::bytes(external_aad.to_vec()),
        CborValue::bytes(payload.to_vec()),
    ]);
    // The structure is a fixed shape of well-formed values; canonical encoding
    // cannot fail (no maps, hence no duplicate-key risk).
    encode_canonical_cbor(&structure).expect("Sig_structure encodes")
}

/// The Label 309 `to_sign` payload: the domain prefix followed by the record body.
fn label309_to_sign(record_body_cbor: &[u8]) -> Vec<u8> {
    let mut to_sign =
        Vec::with_capacity(CARDANO_POE_SIG_DOMAIN_PREFIX.len() + record_body_cbor.len());
    to_sign.extend_from_slice(CARDANO_POE_SIG_DOMAIN_PREFIX.as_bytes());
    to_sign.extend_from_slice(record_body_cbor);
    to_sign
}

/// Build the Label 309 v1 `Sig_structure` for a record body.
///
/// Specialises [`build_sig_structure`] to the v1 invariants:
///
/// - `to_sign = utf8("cardano-poe-record-sig-v1") || record_body_cbor`, where
///   `record_body_cbor` is the canonical CBOR of the record body with the `sigs`
///   field removed. The 25-byte prefix is prepended **internally** — callers
///   MUST NOT pre-concatenate it.
/// - `external_aad` is forced to the empty byte string `h''`.
///
/// `body_protected_bytes` is the COSE_Sign1 protected-header bytes verbatim
/// (`0x40` when the protected header is empty).
#[must_use]
pub fn build_label309_sig_structure(
    body_protected_bytes: &[u8],
    record_body_cbor: &[u8],
) -> Vec<u8> {
    let to_sign = label309_to_sign(record_body_cbor);
    build_sig_structure(body_protected_bytes, &[], &to_sign)
}

// ---------------------------------------------------------------------------
// COSE_Sign1 wire codec
// ---------------------------------------------------------------------------

/// Encode an untagged `COSE_Sign1` 4-element array as canonical CBOR.
///
/// The structure is `[protected, unprotected, payload, signature]`:
///
/// - `protected` is a byte string carrying the canonical-CBOR of the protected
///   header, **or** the zero-length byte string `0x40` when the protected header
///   is empty (RFC 9052 §3 / Label 309 mandate — never `0x41 0xA0`).
/// - `unprotected` is a CBOR map (possibly empty, `0xA0`).
/// - `payload` is the detached `null` (`0xF6`) for Label 309 records, or an
///   attached byte string for the general RFC 9052 form.
/// - `signature` is the 64-byte Ed25519 signature.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] only if a header map contains a duplicate key.
pub fn encode_cose_sign1(
    protected_header: &CoseHeader,
    unprotected_header: &CoseHeader,
    payload: Option<&[u8]>,
    signature: &[u8],
) -> Result<Vec<u8>, CanonicalCborError> {
    let protected_bytes = protected_header.encode_protected()?;
    let payload_value = match payload {
        Some(bytes) => CborValue::bytes(bytes.to_vec()),
        None => CborValue::Null,
    };
    let array = CborValue::Array(vec![
        CborValue::bytes(protected_bytes),
        unprotected_header.to_cbor(),
        payload_value,
        CborValue::bytes(signature.to_vec()),
    ]);
    encode_canonical_cbor(&array)
}

/// A decoded `COSE_Sign1`.
///
/// `protected_bytes` is the raw protected-header byte string as it appeared on
/// the wire — preserved deliberately, because the `Sig_structure` must reuse it
/// verbatim (RFC 9052 §4.4) and never re-encode the decoded header map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoseSign1Decoded {
    /// The decoded protected header (empty when `protected_bytes` is `0x40`).
    pub protected_header: CoseHeader,
    /// The raw protected-header byte string, used verbatim in `Sig_structure`.
    pub protected_bytes: Vec<u8>,
    /// The decoded unprotected header.
    pub unprotected_header: CoseHeader,
    /// The payload byte string, or `None` for the detached (`null`) form.
    pub payload: Option<Vec<u8>>,
    /// The 64-byte signature.
    pub signature: Vec<u8>,
}

/// Decode an untagged `COSE_Sign1` 4-element array.
///
/// Enforces the Label 309 wire constraints: a 4-element top-level array, a
/// byte-string protected header, a map unprotected header, a payload that is
/// either a byte string or `null`, and a 64-byte signature. An empty protected
/// header MUST be the zero-length byte string `0x40`; the 1-byte form `0x41 0xA0`
/// (a byte string wrapping an empty map) is rejected.
///
/// # Errors
///
/// Returns [`CoseDecodeError`] for any structural violation, and folds an
/// underlying canonical-CBOR failure into the same error so the verifier can
/// surface a single `MALFORMED_SIG_COSE` code.
pub fn decode_cose_sign1(bytes: &[u8]) -> Result<CoseSign1Decoded, CoseDecodeError> {
    let value =
        decode_canonical_cbor(bytes).map_err(|_| CoseDecodeError::new("cose decode failed"))?;
    let CborValue::Array(items) = value else {
        return Err(CoseDecodeError::new("expected 4-element array"));
    };
    if items.len() != 4 {
        return Err(CoseDecodeError::new("expected 4-element array"));
    }
    let CborValue::Bytes(protected_bytes) = &items[0] else {
        return Err(CoseDecodeError::new("protected_bytes must be bytes"));
    };
    let unprotected_header = CoseHeader::from_cbor_map(&items[1])
        .ok_or_else(|| CoseDecodeError::new("unprotected header must be map"))?;
    let payload = match &items[2] {
        CborValue::Null => None,
        CborValue::Bytes(b) => Some(b.clone()),
        _ => return Err(CoseDecodeError::new("payload must be bytes or null")),
    };
    let CborValue::Bytes(signature) = &items[3] else {
        return Err(CoseDecodeError::new("signature must be 64 bytes"));
    };
    if signature.len() != ED25519_SIGNATURE_LENGTH {
        return Err(CoseDecodeError::new("signature must be 64 bytes"));
    }

    let protected_header = if protected_bytes.is_empty() {
        CoseHeader::new()
    } else {
        let decoded = decode_canonical_cbor(protected_bytes)
            .map_err(|_| CoseDecodeError::new("protected header decode failed"))?;
        let header = CoseHeader::from_cbor_map(&decoded)
            .ok_or_else(|| CoseDecodeError::new("protected header must decode to map"))?;
        // An empty protected header MUST encode as the single byte 0x40
        // (zero-length bstr), not 0x41 0xA0 (a 1-byte bstr wrapping an empty
        // map). The strict canonical decode above already rejects non-canonical
        // integer widths and key orders inside the protected header.
        if header.is_empty() {
            return Err(CoseDecodeError::new(
                "empty protected header must encode as 0x40 (zero-length bstr), not as an empty map",
            ));
        }
        header
    };

    Ok(CoseSign1Decoded {
        protected_header,
        protected_bytes: protected_bytes.clone(),
        unprotected_header,
        payload,
        signature: signature.clone(),
    })
}

/// A structural `COSE_Sign1` decode failure.
///
/// Every decode-time violation collapses to the single
/// [`CoseVerifyErrorCode::MalformedSigCose`] code; this type carries a
/// human-readable detail string for diagnostics while the verifier exposes only
/// the stable code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("MALFORMED_SIG_COSE: {detail}")]
pub struct CoseDecodeError {
    /// A human-readable description of the structural violation.
    pub detail: String,
}

impl CoseDecodeError {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Stable error codes a `COSE_Sign1` verification can fail with.
///
/// These match the `code` strings on the TypeScript and Python twins
/// byte-for-byte, so cross-implementation tests assert the exact same value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoseVerifyErrorCode {
    /// The `COSE_Sign1` is structurally malformed (bad array shape, non-canonical
    /// CBOR, wrong field types, an empty protected header encoded as a map, …).
    MalformedSigCose,
    /// The `COSE_Sign1` carries an attached payload where Label 309 mandates a
    /// detached (`null`) payload — including a zero-length byte string `h''`.
    MalformedSigCoseSign1,
    /// The protected-header algorithm is not EdDSA (`-8`).
    UnsupportedSigAlg,
    /// No signer key could be resolved: neither a 32-byte `kid` in the protected
    /// header nor an out-of-band `expected_signer_key`, or the two disagree.
    KidUnresolved,
    /// The signature did not verify under strict Ed25519.
    SignatureInvalid,
}

impl CoseVerifyErrorCode {
    /// The stable wire string for this code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            CoseVerifyErrorCode::MalformedSigCose => "MALFORMED_SIG_COSE",
            CoseVerifyErrorCode::MalformedSigCoseSign1 => "MALFORMED_SIG_COSE_SIGN1",
            CoseVerifyErrorCode::UnsupportedSigAlg => "UNSUPPORTED_SIG_ALG",
            CoseVerifyErrorCode::KidUnresolved => "KID_UNRESOLVED",
            CoseVerifyErrorCode::SignatureInvalid => "SIGNATURE_INVALID",
        }
    }
}

/// The outcome of a `COSE_Sign1` verification.
///
/// On success it carries the resolved 32-byte signer key and the algorithm; on
/// failure, the stable error code. Mirrors the discriminated result the other
/// SDKs return rather than using `Result`, because a failed verdict is a normal
/// (non-exceptional) outcome the caller inspects by code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoseVerifyResult {
    /// The signature verified.
    Ok {
        /// The 32-byte Ed25519 public key that produced the signature.
        signer_key: [u8; 32],
        /// The signature algorithm (always `-8`, EdDSA, in Label 309 v1).
        alg: i64,
    },
    /// The signature did not verify; carries the stable error code.
    Err(CoseVerifyErrorCode),
}

impl CoseVerifyResult {
    /// `true` if verification succeeded.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(self, CoseVerifyResult::Ok { .. })
    }
}

/// Errors from the Label 309 record-signature builder.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CoseSign1BuildError {
    /// Neither a secret seed nor a signer closure was provided. Also returned
    /// when an injected signer returns a value that is not exactly 64 bytes,
    /// matching the TypeScript/Python twins (which reuse this code rather than
    /// adding a separate one for the bad-length case).
    #[error("SIGNER_NOT_PROVIDED: {0}")]
    SignerNotProvided(String),
    /// Both a secret seed and a signer closure were provided; exactly one is
    /// permitted.
    #[error("SIGNER_AND_SEED_BOTH_PROVIDED: {0}")]
    SignerAndSeedBothProvided(String),
}

impl CoseSign1BuildError {
    /// The stable wire string for this build error's code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            CoseSign1BuildError::SignerNotProvided(_) => "SIGNER_NOT_PROVIDED",
            CoseSign1BuildError::SignerAndSeedBothProvided(_) => "SIGNER_AND_SEED_BOTH_PROVIDED",
        }
    }
}

// ---------------------------------------------------------------------------
// Label 309 record-signature build
// ---------------------------------------------------------------------------

/// How to produce the 64-byte Ed25519 signature in [`cose_sign1_label309_build`].
///
/// Exactly one variant is permitted. The seed path is used by tests, by the
/// Python/TypeScript parity harness, and by the off-host signing helper; the
/// closure path keeps a private key inside an unlock-store closure so the raw
/// seed never escapes its scope (composer-side use).
pub enum Label309Signer<'a> {
    /// Sign with the raw 32-byte Ed25519 seed.
    Seed(&'a [u8; 32]),
    /// Sign by invoking a closure over the assembled `Sig_structure` bytes. The
    /// closure must return exactly 64 bytes.
    Closure(&'a dyn Fn(&[u8]) -> Vec<u8>),
}

/// Build a Label 309 v1 record signature as a detached `COSE_Sign1`.
///
/// Steps:
///
/// 1. Encode the protected header (`0x40` if empty).
/// 2. Compute `Sig_structure` over
///    `to_sign = utf8("cardano-poe-record-sig-v1") || record_body_cbor` — the
///    25-byte prefix is prepended internally; callers MUST NOT pre-concatenate.
/// 3. Ed25519-sign the `Sig_structure` (via seed or injected closure).
/// 4. Emit a `COSE_Sign1` with a detached (`null`) payload.
///
/// # Errors
///
/// Returns [`CoseSign1BuildError::SignerNotProvided`] if a closure returns a
/// non-64-byte value, and [`CanonicalCborError`] only if a header map carries a
/// duplicate key. The seed/closure exclusivity is encoded in the [`Label309Signer`]
/// enum, so the both-provided case is unrepresentable here.
pub fn cose_sign1_label309_build(
    protected_header: &CoseHeader,
    unprotected_header: &CoseHeader,
    record_body_cbor: &[u8],
    signer: Label309Signer<'_>,
) -> Result<Vec<u8>, CoseSign1BuildError> {
    let protected_bytes = encode_protected_bytes(protected_header)?;
    let sig_structure = build_label309_sig_structure(&protected_bytes, record_body_cbor);
    let signature = match signer {
        Label309Signer::Seed(seed) => ed25519_sign(seed, &sig_structure).to_vec(),
        Label309Signer::Closure(closure) => {
            let sig = closure(&sig_structure);
            if sig.len() != ED25519_SIGNATURE_LENGTH {
                return Err(CoseSign1BuildError::SignerNotProvided(format!(
                    "injected signer must return a 64-byte value; got {} bytes",
                    sig.len()
                )));
            }
            sig
        }
    };
    encode_cose_sign1(protected_header, unprotected_header, None, &signature)
        .map_err(|e| CoseSign1BuildError::SignerNotProvided(e.to_string()))
}

/// Encode a protected header to its on-wire bytes (`0x40` payload when empty).
///
/// Returns the canonical-CBOR map bytes for a non-empty header, or an empty
/// vector (which [`encode_cose_sign1`] / [`build_sig_structure`] carry as the
/// zero-length `0x40` byte string) for an empty header.
fn encode_protected_bytes(protected_header: &CoseHeader) -> Result<Vec<u8>, CoseSign1BuildError> {
    protected_header
        .encode_protected()
        .map_err(|e| CoseSign1BuildError::SignerNotProvided(e.to_string()))
}

// ---------------------------------------------------------------------------
// Off-host prepare / assemble
// ---------------------------------------------------------------------------

/// The output of [`cose_sign1_label309_prepare`]: everything an external signer and
/// the subsequent [`cose_sign1_label309_assemble`] call need.
///
/// `sig_structure` is the exact bytes the external signer must Ed25519-sign.
/// `protected_header` and `unprotected_header` are carried so `assemble` can fold
/// the returned signature into the final `COSE_Sign1` without recomputing them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label309Prepared {
    /// The `Sig_structure` bytes the external signer must Ed25519-sign.
    pub sig_structure: Vec<u8>,
    /// The protected header to embed in the assembled `COSE_Sign1`.
    pub protected_header: CoseHeader,
    /// The unprotected header to embed in the assembled `COSE_Sign1`.
    pub unprotected_header: CoseHeader,
}

/// Prepare an off-host Label 309 record signature.
///
/// Returns the exact `Sig_structure` bytes an external signer (a wallet, an HSM,
/// an air-gapped device) must Ed25519-sign, alongside the headers needed to
/// reassemble the final `COSE_Sign1`. The 25-byte domain prefix is prepended
/// internally; the caller passes only the canonical record body (with `sigs`
/// removed).
///
/// This is the byte-identical split of [`cose_sign1_label309_build`]: the
/// `sig_structure` it returns equals the bytes the build path signs.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] only if the protected header carries a
/// duplicate key.
pub fn cose_sign1_label309_prepare(
    protected_header: &CoseHeader,
    unprotected_header: &CoseHeader,
    record_body_cbor: &[u8],
) -> Result<Label309Prepared, CanonicalCborError> {
    let protected_bytes = protected_header.encode_protected()?;
    Ok(Label309Prepared {
        sig_structure: build_label309_sig_structure(&protected_bytes, record_body_cbor),
        protected_header: protected_header.clone(),
        unprotected_header: unprotected_header.clone(),
    })
}

/// Assemble a Label 309 `COSE_Sign1` from an external 64-byte signature.
///
/// Takes the [`Label309Prepared`] returned by [`cose_sign1_label309_prepare`] and the
/// 64-byte signature the external signer produced over `prepared.sig_structure`,
/// and emits the final detached-payload `COSE_Sign1`.
///
/// # Errors
///
/// Returns [`CoseSign1BuildError::SignerNotProvided`] if `signature` is not
/// exactly 64 bytes, and folds a duplicate-key header failure into the same code.
pub fn cose_sign1_label309_assemble(
    prepared: &Label309Prepared,
    signature: &[u8],
) -> Result<Vec<u8>, CoseSign1BuildError> {
    if signature.len() != ED25519_SIGNATURE_LENGTH {
        return Err(CoseSign1BuildError::SignerNotProvided(format!(
            "external signature must be 64 bytes; got {} bytes",
            signature.len()
        )));
    }
    encode_cose_sign1(
        &prepared.protected_header,
        &prepared.unprotected_header,
        None,
        signature,
    )
    .map_err(|e| CoseSign1BuildError::SignerNotProvided(e.to_string()))
}

// ---------------------------------------------------------------------------
// Label 309 record-signature verify
// ---------------------------------------------------------------------------

/// Verify a Label 309 v1 record signature.
///
/// `message` is the encoded `COSE_Sign1`. `detached_record_body_cbor` is the
/// verifier-recomputed canonical record body (with `sigs` removed); the 25-byte
/// domain prefix is prepended internally. `expected_signer_key`, when present, is
/// the out-of-band signer key for the CIP-30 wallet path (resolved from
/// `sigs[i].cose_key`), used when the protected header carries no `kid`.
///
/// The verification order is fixed:
///
/// 1. Decode the `COSE_Sign1` (→ [`CoseVerifyErrorCode::MalformedSigCose`]).
/// 2. Reject any non-`null` payload (→
///    [`CoseVerifyErrorCode::MalformedSigCoseSign1`]).
/// 3. Require `alg = -8` (→ [`CoseVerifyErrorCode::UnsupportedSigAlg`]).
/// 4. Resolve the signer key from the 32-byte `kid` or `expected_signer_key`;
///    if both are present they must match (constant-time) (→
///    [`CoseVerifyErrorCode::KidUnresolved`]).
/// 5. Hashed mode: when the unprotected header carries `"hashed": true`, sign
///    `Sig_structure[3] = BLAKE2b-224(to_sign)` (CIP-8); otherwise use the
///    full `to_sign` payload.
/// 6. Strict Ed25519 verify (→ [`CoseVerifyErrorCode::SignatureInvalid`]).
#[must_use]
pub fn cose_sign1_label309_verify(
    message: &[u8],
    detached_record_body_cbor: &[u8],
    expected_signer_key: Option<&[u8]>,
) -> CoseVerifyResult {
    let decoded = match decode_cose_sign1(message) {
        Ok(d) => d,
        Err(_) => return CoseVerifyResult::Err(CoseVerifyErrorCode::MalformedSigCose),
    };

    // Label 309 mandates a detached (null) payload. Any attached payload —
    // including a zero-length byte string h'' — is rejected.
    if decoded.payload.is_some() {
        return CoseVerifyResult::Err(CoseVerifyErrorCode::MalformedSigCoseSign1);
    }

    // Require EdDSA (alg = -8) in the protected header.
    if decoded.protected_header.alg() != Some(COSE_ALG_EDDSA) {
        return CoseVerifyResult::Err(CoseVerifyErrorCode::UnsupportedSigAlg);
    }

    // Resolve the signer key: a 32-byte kid in the protected header, or the
    // out-of-band expected_signer_key. If both are present they must agree.
    let kid: Option<[u8; 32]> = decoded.protected_header.kid();
    let expected: Option<[u8; 32]> = match expected_signer_key {
        Some(k) if k.len() == ED25519_PUBLIC_KEY_LENGTH => k.try_into().ok(),
        _ => None,
    };
    if let (Some(kid_bytes), Some(expected_bytes)) = (&kid, &expected) {
        if kid_bytes.ct_eq(expected_bytes).unwrap_u8() != 1 {
            return CoseVerifyResult::Err(CoseVerifyErrorCode::KidUnresolved);
        }
    }
    let signer_key = match kid.or(expected) {
        Some(k) => k,
        None => return CoseVerifyResult::Err(CoseVerifyErrorCode::KidUnresolved),
    };

    // CIP-8 hashed mode: when the unprotected header carries `"hashed": true`,
    // the signed payload is BLAKE2b-224 of the full to_sign (prefix + body);
    // otherwise the signed payload is to_sign itself.
    let hashed = matches!(
        decoded.unprotected_header.get_text(HASHED_MODE_HEADER_KEY),
        Some(CborValue::Bool(true))
    );
    let sig_structure = if hashed {
        let to_sign = label309_to_sign(detached_record_body_cbor);
        let digest = blake2b224(&to_sign);
        build_sig_structure(&decoded.protected_bytes, &[], &digest)
    } else {
        build_label309_sig_structure(&decoded.protected_bytes, detached_record_body_cbor)
    };

    if ed25519_verify(&signer_key, &sig_structure, &decoded.signature) {
        CoseVerifyResult::Ok {
            signer_key,
            alg: COSE_ALG_EDDSA,
        }
    } else {
        CoseVerifyResult::Err(CoseVerifyErrorCode::SignatureInvalid)
    }
}

/// Read a CBOR integer value as an `i64`, returning `None` for non-integers or
/// out-of-range magnitudes.
fn cbor_int_value(value: Option<&CborValue>) -> Option<i64> {
    match value {
        Some(CborValue::Unsigned(n)) => i64::try_from(*n).ok(),
        Some(CborValue::Negative(m)) => {
            let signed = -1_i128 - i128::from(*m);
            i64::try_from(signed).ok()
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// COSE_Key decoder
// ---------------------------------------------------------------------------

/// Decode an OKP/Ed25519 `COSE_Key` to its raw 32-byte public key.
///
/// CIP-30 wallets that do not place a raw Ed25519 public key in the COSE_Sign1
/// protected header instead deliver the signer key as a separate
/// `cbor<COSE_Key>` blob (surfaced on a Label 309 record under `sigs[i].cose_key`).
/// This helper decodes one such blob and returns the 32-byte public key, or
/// `None` when the blob is malformed, uses an unexpected key type / curve, has a
/// wrong-length `x`, or carries an algorithm other than EdDSA.
///
/// The expected shape (RFC 9053 §7.2 + RFC 8152 §13) is:
///
/// ```text
/// {  1 (kty): 1   // OKP
///    3 (alg): -8  // EdDSA — OPTIONAL, but if present MUST be -8
///   -1 (crv): 6   // Ed25519
///   -2 (x):   <32-byte raw public key> }
/// ```
#[must_use]
pub fn parse_cose_key_ed25519(blob: &[u8]) -> Option<[u8; 32]> {
    const LABEL_KTY: i64 = 1;
    const LABEL_ALG: i64 = 3;
    const LABEL_CRV: i64 = -1;
    const LABEL_X: i64 = -2;
    const KTY_OKP: i64 = 1;
    const ALG_EDDSA: i64 = -8;
    const CRV_ED25519: i64 = 6;

    let decoded = decode_canonical_cbor(blob).ok()?;
    let header = CoseHeader::from_cbor_map(&decoded)?;

    if cbor_int_value(header.get_int(LABEL_KTY)) != Some(KTY_OKP) {
        return None;
    }
    if cbor_int_value(header.get_int(LABEL_CRV)) != Some(CRV_ED25519) {
        return None;
    }
    if let Some(alg) = header.get_int(LABEL_ALG) {
        if cbor_int_value(Some(alg)) != Some(ALG_EDDSA) {
            return None;
        }
    }
    match header.get_int(LABEL_X) {
        Some(CborValue::Bytes(x)) if x.len() == ED25519_PUBLIC_KEY_LENGTH => {
            Some(x.as_slice().try_into().ok()?)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_prefix_is_pinned_25_bytes() {
        assert_eq!(CARDANO_POE_SIG_DOMAIN_PREFIX, "cardano-poe-record-sig-v1");
        assert_eq!(CARDANO_POE_SIG_DOMAIN_PREFIX.len(), 25);
        assert_eq!(
            crate::hex::encode(CARDANO_POE_SIG_DOMAIN_PREFIX.as_bytes()),
            "63617264616e6f2d706f652d7265636f72642d7369672d7631"
        );
    }

    #[test]
    fn empty_protected_header_encodes_as_0x40() {
        // {1:-8,4:<32B>} unprotected absent: build with an empty protected header
        // and confirm the COSE_Sign1[0] element is the single byte 0x40.
        let cose = encode_cose_sign1(
            &CoseHeader::new(),
            &CoseHeader::new(),
            None,
            &[0u8; ED25519_SIGNATURE_LENGTH],
        )
        .unwrap();
        // Top-level array(4) = 0x84, then the protected element = 0x40.
        assert_eq!(cose[0], 0x84);
        assert_eq!(cose[1], 0x40);
    }

    #[test]
    fn blake2b224_is_parameterized_28_bytes() {
        // The 28-byte parameterized BLAKE2b digest of the empty input.
        let digest = blake2b224(b"");
        assert_eq!(digest.len(), 28);
        assert_eq!(
            crate::hex::encode(&digest),
            "836cc68931c2e4e3e838602eca1902591d216837bafddfe6f0c8cb07"
        );
    }

    #[test]
    fn ed25519_strict_rejects_low_order_pubkey() {
        // C2SP/CCTV low-order-A vector: cofactored verify accepts, strict rejects.
        let pk =
            crate::hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let msg = crate::hex::decode("65643235353139766563746f72732033").unwrap();
        let sig = crate::hex::decode(
            "36684ea91032ba5b1dbab2d02f4debc74c3327f2b3802e2e4d371aa42b12b56b05ba9a796274d80437afa36f1236563f2f3b0aa84cecddc3d20914615ba4fe02",
        )
        .unwrap();
        assert!(!ed25519_verify(&pk, &msg, &sig));
    }

    #[test]
    fn prepare_sig_structure_equals_build_signed_bytes() {
        // The prepare path must produce the exact bytes the build path signs.
        let pk = ed25519_public_key_from_seed(&[0x11; 32]);
        let protected = CoseHeader::new()
            .with_int(COSE_HEADER_LABEL_ALG, CborValue::int(COSE_ALG_EDDSA))
            .with_int(COSE_HEADER_LABEL_KID, CborValue::bytes(pk.to_vec()));
        let body = crate::hex::decode("a16161182a").unwrap();
        let prepared = cose_sign1_label309_prepare(&protected, &CoseHeader::new(), &body).unwrap();
        let protected_bytes = encode_canonical_cbor(&protected.to_cbor()).unwrap();
        let direct = build_label309_sig_structure(&protected_bytes, &body);
        assert_eq!(prepared.sig_structure, direct);
    }
}
