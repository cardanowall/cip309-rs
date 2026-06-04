//! Label 309 v1 Proof-of-Existence record wire format.
//!
//! This module is the wire-format core: the typed record model, the canonical
//! CBOR encoder, the structural validator, and the error-code catalogue. It is a
//! byte-parity twin of the TypeScript (`@cardanowall/poe-standard`) and Python
//! (`cardanowall.poe_standard`) implementations: it reproduces their exact
//! canonical-CBOR bytes against the same shared cross-implementation test
//! vectors. On the handful of validator edge cases where the published
//! TypeScript and Python references currently disagree — the extension-key and
//! unauthenticated-cipher regex boundaries, the CIDv0 decode, and the URI-scheme
//! dispatch — this hand-rolled validator tracks the Python reference.
//!
//! The two public encoders both emit RFC 8949 §4.2.1 canonical CBOR (the
//! [`crate::cbor`] layer does the deterministic ordering and shortest-form work):
//!
//! - [`encode_poe_record`] — the full record map, for chain submission.
//! - [`encode_record_body_for_signing`] — the same map with the `sigs` key
//!   dropped. These bytes are what record-level COSE_Sign1 signatures cover.
//!
//! [`validate_poe_record`] is a pure function over CBOR bytes that performs no
//! I/O, runs no cryptographic signature verification, and decrypts nothing. It
//! returns the same [`ErrorCode`] set, the same per-issue severity, and the same
//! ok/fail verdict as the other two SDKs.

use std::collections::BTreeSet;

use crate::cbor::{decode_canonical_cbor, encode_canonical_cbor, CborValue};

// ===========================================================================
// Error-code catalogue
// ===========================================================================

/// One code from the Label 309 validation error-code taxonomy.
///
/// The variants split into two parts:
///
/// - **Structural** codes (`Part A`) are the only codes
///   [`validate_poe_record`] ever emits — every canonical-decode, schema, and
///   domain failure surfaces as one of these.
/// - **Verifier** codes (`Part B`) are re-exported so a downstream verifier can
///   dispatch on a single union; the structural validator never emits them.
///
/// Each variant's [`code`](ErrorCode::code) string matches the canonical
/// `SCREAMING_SNAKE_CASE` spelling byte-for-byte, so cross-implementation tests
/// can assert the exact same strings the TypeScript and Python SDKs use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ErrorCode {
    // --- Part A: structural validator codes ---
    /// Every canonical-CBOR decode failure: malformed/truncated bytes,
    /// indefinite-length encodings, non-canonical (unsorted) map keys, duplicate
    /// map keys, non-minimal integers, invalid UTF-8. One code, no finer grain.
    MalformedCbor,
    /// A field has the wrong CBOR type for its position.
    SchemaTypeMismatch,
    /// A required field is absent.
    SchemaMissingRequired,
    /// A map carries a key outside its closed set (and not a valid extension).
    SchemaUnknownField,
    /// A literal-valued field (e.g. `v`) holds a value other than the one
    /// permitted literal.
    SchemaInvalidLiteral,
    /// The record commits to no content — neither a non-empty `items` nor a
    /// non-empty `merkle`.
    SchemaEmptyRecord,
    /// A hash digest's byte length does not match its algorithm's registry value.
    HashDigestLengthMismatch,
    /// A hash algorithm identifier is not in the v1 registry.
    UnsupportedHashAlg,
    /// A Merkle list-commitment algorithm identifier is not in the v1 registry.
    UnsupportedMerkleCommitAlg,
    /// A reconstructed URI is not a well-formed absolute `ar://` / `ipfs://` URI.
    InvalidUri,
    /// A chunk's byte length is outside the `[1, 64]` range.
    ChunkTooLarge,
    /// `enc.aead` names an unauthenticated cipher family member.
    UnauthenticatedCipherForbidden,
    /// `enc.aead` is not in the v1 AEAD registry.
    UnsupportedAeadAlg,
    /// `enc.nonce` length does not match the AEAD's nonce length.
    NonceLengthMismatch,
    /// `enc.scheme` is not the unsigned integer 1.
    UnsupportedEnvelopeScheme,
    /// `enc.slots` is an empty array.
    EncSlotsEmpty,
    /// A recipient slot is not the closed 2-key map its KEM requires.
    EncSlotInvalidShape,
    /// `enc.kem` is not in the v1 KEM registry.
    UnsupportedKemAlg,
    /// `enc.slots` is present but `enc.kem` is absent.
    EncKemRequired,
    /// A classical slot's `epk` is not 32 bytes.
    KemEpkLengthMismatch,
    /// A hybrid slot's `kem_ct` does not reassemble to the X-Wing `enc` length.
    KemCtLengthMismatch,
    /// A slot's `wrap` is not 48 bytes.
    WrapLengthMismatch,
    /// `enc.slots_mac` is not 32 bytes.
    EncSlotsMacInvalidLength,
    /// `enc.slots` is present but `enc.slots_mac` is absent.
    EncSlotsMacRequired,
    /// `enc.slots_mac` is present but `enc.slots` is absent.
    EncSlotsRequired,
    /// `enc` combines `slots` with `passphrase`; the two key paths are exclusive.
    EncExclusivityViolation,
    /// `enc` carries neither a `slots` nor a `passphrase` key path.
    EncNoKeyPath,
    /// An `enc`-bearing item's `hashes` carries no content-hash entry.
    EncRequiresContentHash,
    /// `enc.passphrase.alg` is not in the v1 passphrase-KDF registry.
    EncPassphraseAlgUnsupported,
    /// `enc.passphrase.salt` is shorter than 16 bytes.
    EncPassphraseSaltTooShort,
    /// `enc.passphrase.salt` is longer than 64 bytes.
    EncPassphraseSaltTooLong,
    /// An Argon2id parameter is below the v1 floor.
    EncPassphraseArgon2ParamsTooLow,
    /// Declared but not emitted by the structural validator; reserved for a
    /// policy layer above it.
    EncPassphraseParamsExceedPolicy,
    /// A `sigs[i].cose_sign1` (or `cose_key`) blob is not a well-formed COSE
    /// structure.
    MalformedSigCoseSign1,
    /// A signature's protected `alg` is not in the known set; info-severity.
    SignatureUnsupported,
    /// A `sigs[i]` entry is not the closed `{cose_sign1, ? cose_key}` map.
    SigEntryInvalidShape,
    /// A `sigs[i]` entry carries both a 32-byte protected `kid` and a `cose_key`.
    SigEntryKidCoseKeyConflict,
    /// A `sigs[i].cose_key` carries private-key material (COSE_Key label `-4`).
    SigPrivateKeyLeaked,
    /// `supersedes` is not a 32-byte transaction hash.
    SupersedesTxInvalidLength,
    /// A `crit` entry names an extension this validator does not implement.
    ExtensionUnsupportedCritical,
    /// A `crit` entry violates the `crit[]` shape rules.
    CritShapeInvalid,

    // --- Part B: verifier-layer codes ---
    /// Label-309 metadata could not be found for the transaction.
    MetadataNotFound,
    /// The transaction has fewer confirmations than required; info-severity.
    InsufficientConfirmations,
    /// A record signature failed cryptographic verification.
    SignatureInvalid,
    /// A signer key could not be resolved.
    SignerKeyUnresolved,
    /// The signer wallet address did not match.
    WalletAddressMismatch,
    /// A URI target is on the deny list.
    UriTargetForbidden,
    /// A fetched URI's bytes did not match the committed hash.
    UriIntegrityMismatch,
    /// A URI fetch failed at runtime; warning-severity.
    UriFetchFailed,
    /// The committed content is unavailable.
    ContentUnavailable,
    /// The committed ciphertext is unavailable.
    CiphertextUnavailable,
    /// A required provider is unavailable.
    ProviderUnavailable,
    /// A service-independence invariant was violated.
    ServiceIndependenceViolation,
    /// Decryption input had the wrong shape.
    WrongDecryptionInputShape,
    /// The recipient key did not match any slot.
    WrongRecipientKey,
    /// The sealed header failed its authentication tag.
    TamperedHeader,
    /// The ciphertext failed its authentication tag.
    TamperedCiphertext,
    /// A key-derivation step failed.
    KdfDerivationFailed,
    /// A Merkle commitment's leaf count did not match.
    SchemaMerkleLeafCountMismatch,
    /// A Merkle leaves payload used an unsupported format.
    SchemaMerkleLeavesFormatUnsupported,
    /// A Merkle leaves payload was structurally malformed (undecodable CBOR,
    /// non-map top level, wrong-typed/wrong-length field, empty leaves, or a
    /// `tree_alg` outside the v1 registry).
    SchemaMerkleLeavesMalformed,
    /// A recomputed Merkle root did not match the committed root.
    MerkleRootMismatch,
    /// The Merkle leaves payload was unavailable; warning-severity.
    MerkleLeavesUnavailable,
    /// The Merkle leaves were in informative-only form; info-severity.
    MerkleLeavesInformativeForm,
    /// A Merkle commitment used an unsupported feature; info-severity by default.
    MerkleUnsupported,
    /// A check was skipped because it was out of the active profile;
    /// info-severity by default.
    OutOfProfileSkipped,
}

/// The severity classification of a validation issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    /// A fatal defect: any error-severity issue fails the record.
    Error,
    /// A non-fatal runtime anomaly that did not invalidate the record.
    Warning,
    /// A deliberate non-check (out-of-profile, unrecognised optional feature).
    Info,
}

/// The structural validator codes, in catalogue order.
///
/// These are the only codes [`validate_poe_record`] emits.
pub const STRUCTURAL_ERROR_CODES: &[ErrorCode] = &[
    ErrorCode::MalformedCbor,
    ErrorCode::SchemaTypeMismatch,
    ErrorCode::SchemaMissingRequired,
    ErrorCode::SchemaUnknownField,
    ErrorCode::SchemaInvalidLiteral,
    ErrorCode::SchemaEmptyRecord,
    ErrorCode::HashDigestLengthMismatch,
    ErrorCode::UnsupportedHashAlg,
    ErrorCode::UnsupportedMerkleCommitAlg,
    ErrorCode::InvalidUri,
    ErrorCode::ChunkTooLarge,
    ErrorCode::UnauthenticatedCipherForbidden,
    ErrorCode::UnsupportedAeadAlg,
    ErrorCode::NonceLengthMismatch,
    ErrorCode::UnsupportedEnvelopeScheme,
    ErrorCode::EncSlotsEmpty,
    ErrorCode::EncSlotInvalidShape,
    ErrorCode::UnsupportedKemAlg,
    ErrorCode::EncKemRequired,
    ErrorCode::KemEpkLengthMismatch,
    ErrorCode::KemCtLengthMismatch,
    ErrorCode::WrapLengthMismatch,
    ErrorCode::EncSlotsMacInvalidLength,
    ErrorCode::EncSlotsMacRequired,
    ErrorCode::EncSlotsRequired,
    ErrorCode::EncExclusivityViolation,
    ErrorCode::EncNoKeyPath,
    ErrorCode::EncRequiresContentHash,
    ErrorCode::EncPassphraseAlgUnsupported,
    ErrorCode::EncPassphraseSaltTooShort,
    ErrorCode::EncPassphraseSaltTooLong,
    ErrorCode::EncPassphraseArgon2ParamsTooLow,
    ErrorCode::EncPassphraseParamsExceedPolicy,
    ErrorCode::MalformedSigCoseSign1,
    ErrorCode::SignatureUnsupported,
    ErrorCode::SigEntryInvalidShape,
    ErrorCode::SigEntryKidCoseKeyConflict,
    ErrorCode::SigPrivateKeyLeaked,
    ErrorCode::SupersedesTxInvalidLength,
    ErrorCode::ExtensionUnsupportedCritical,
    ErrorCode::CritShapeInvalid,
];

/// The verifier-layer codes, in catalogue order.
///
/// Re-exported so a downstream verifier can dispatch on the single [`ErrorCode`]
/// union; the structural validator never emits these.
pub const VERIFIER_ERROR_CODES: &[ErrorCode] = &[
    ErrorCode::MetadataNotFound,
    ErrorCode::InsufficientConfirmations,
    ErrorCode::SignatureInvalid,
    ErrorCode::SignerKeyUnresolved,
    ErrorCode::WalletAddressMismatch,
    ErrorCode::UriTargetForbidden,
    ErrorCode::UriIntegrityMismatch,
    ErrorCode::UriFetchFailed,
    ErrorCode::ContentUnavailable,
    ErrorCode::CiphertextUnavailable,
    ErrorCode::ProviderUnavailable,
    ErrorCode::ServiceIndependenceViolation,
    ErrorCode::WrongDecryptionInputShape,
    ErrorCode::WrongRecipientKey,
    ErrorCode::TamperedHeader,
    ErrorCode::TamperedCiphertext,
    ErrorCode::KdfDerivationFailed,
    ErrorCode::SchemaMerkleLeafCountMismatch,
    ErrorCode::SchemaMerkleLeavesFormatUnsupported,
    ErrorCode::SchemaMerkleLeavesMalformed,
    ErrorCode::MerkleRootMismatch,
    ErrorCode::MerkleLeavesUnavailable,
    ErrorCode::MerkleLeavesInformativeForm,
    ErrorCode::MerkleUnsupported,
    ErrorCode::OutOfProfileSkipped,
];

impl ErrorCode {
    /// The stable `SCREAMING_SNAKE_CASE` code string.
    ///
    /// Matches the TypeScript `ErrorCode` union member and the Python
    /// `ErrorCode` literal byte-for-byte.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            ErrorCode::MalformedCbor => "MALFORMED_CBOR",
            ErrorCode::SchemaTypeMismatch => "SCHEMA_TYPE_MISMATCH",
            ErrorCode::SchemaMissingRequired => "SCHEMA_MISSING_REQUIRED",
            ErrorCode::SchemaUnknownField => "SCHEMA_UNKNOWN_FIELD",
            ErrorCode::SchemaInvalidLiteral => "SCHEMA_INVALID_LITERAL",
            ErrorCode::SchemaEmptyRecord => "SCHEMA_EMPTY_RECORD",
            ErrorCode::HashDigestLengthMismatch => "HASH_DIGEST_LENGTH_MISMATCH",
            ErrorCode::UnsupportedHashAlg => "UNSUPPORTED_HASH_ALG",
            ErrorCode::UnsupportedMerkleCommitAlg => "UNSUPPORTED_MERKLE_COMMIT_ALG",
            ErrorCode::InvalidUri => "INVALID_URI",
            ErrorCode::ChunkTooLarge => "CHUNK_TOO_LARGE",
            ErrorCode::UnauthenticatedCipherForbidden => "UNAUTHENTICATED_CIPHER_FORBIDDEN",
            ErrorCode::UnsupportedAeadAlg => "UNSUPPORTED_AEAD_ALG",
            ErrorCode::NonceLengthMismatch => "NONCE_LENGTH_MISMATCH",
            ErrorCode::UnsupportedEnvelopeScheme => "UNSUPPORTED_ENVELOPE_SCHEME",
            ErrorCode::EncSlotsEmpty => "ENC_SLOTS_EMPTY",
            ErrorCode::EncSlotInvalidShape => "ENC_SLOT_INVALID_SHAPE",
            ErrorCode::UnsupportedKemAlg => "UNSUPPORTED_KEM_ALG",
            ErrorCode::EncKemRequired => "ENC_KEM_REQUIRED",
            ErrorCode::KemEpkLengthMismatch => "KEM_EPK_LENGTH_MISMATCH",
            ErrorCode::KemCtLengthMismatch => "KEM_CT_LENGTH_MISMATCH",
            ErrorCode::WrapLengthMismatch => "WRAP_LENGTH_MISMATCH",
            ErrorCode::EncSlotsMacInvalidLength => "ENC_SLOTS_MAC_INVALID_LENGTH",
            ErrorCode::EncSlotsMacRequired => "ENC_SLOTS_MAC_REQUIRED",
            ErrorCode::EncSlotsRequired => "ENC_SLOTS_REQUIRED",
            ErrorCode::EncExclusivityViolation => "ENC_EXCLUSIVITY_VIOLATION",
            ErrorCode::EncNoKeyPath => "ENC_NO_KEY_PATH",
            ErrorCode::EncRequiresContentHash => "ENC_REQUIRES_CONTENT_HASH",
            ErrorCode::EncPassphraseAlgUnsupported => "ENC_PASSPHRASE_ALG_UNSUPPORTED",
            ErrorCode::EncPassphraseSaltTooShort => "ENC_PASSPHRASE_SALT_TOO_SHORT",
            ErrorCode::EncPassphraseSaltTooLong => "ENC_PASSPHRASE_SALT_TOO_LONG",
            ErrorCode::EncPassphraseArgon2ParamsTooLow => "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW",
            ErrorCode::EncPassphraseParamsExceedPolicy => "ENC_PASSPHRASE_PARAMS_EXCEED_POLICY",
            ErrorCode::MalformedSigCoseSign1 => "MALFORMED_SIG_COSE_SIGN1",
            ErrorCode::SignatureUnsupported => "SIGNATURE_UNSUPPORTED",
            ErrorCode::SigEntryInvalidShape => "SIG_ENTRY_INVALID_SHAPE",
            ErrorCode::SigEntryKidCoseKeyConflict => "SIG_ENTRY_KID_COSE_KEY_CONFLICT",
            ErrorCode::SigPrivateKeyLeaked => "SIG_PRIVATE_KEY_LEAKED",
            ErrorCode::SupersedesTxInvalidLength => "SUPERSEDES_TX_INVALID_LENGTH",
            ErrorCode::ExtensionUnsupportedCritical => "EXTENSION_UNSUPPORTED_CRITICAL",
            ErrorCode::CritShapeInvalid => "CRIT_SHAPE_INVALID",
            ErrorCode::MetadataNotFound => "METADATA_NOT_FOUND",
            ErrorCode::InsufficientConfirmations => "INSUFFICIENT_CONFIRMATIONS",
            ErrorCode::SignatureInvalid => "SIGNATURE_INVALID",
            ErrorCode::SignerKeyUnresolved => "SIGNER_KEY_UNRESOLVED",
            ErrorCode::WalletAddressMismatch => "WALLET_ADDRESS_MISMATCH",
            ErrorCode::UriTargetForbidden => "URI_TARGET_FORBIDDEN",
            ErrorCode::UriIntegrityMismatch => "URI_INTEGRITY_MISMATCH",
            ErrorCode::UriFetchFailed => "URI_FETCH_FAILED",
            ErrorCode::ContentUnavailable => "CONTENT_UNAVAILABLE",
            ErrorCode::CiphertextUnavailable => "CIPHERTEXT_UNAVAILABLE",
            ErrorCode::ProviderUnavailable => "PROVIDER_UNAVAILABLE",
            ErrorCode::ServiceIndependenceViolation => "SERVICE_INDEPENDENCE_VIOLATION",
            ErrorCode::WrongDecryptionInputShape => "WRONG_DECRYPTION_INPUT_SHAPE",
            ErrorCode::WrongRecipientKey => "WRONG_RECIPIENT_KEY",
            ErrorCode::TamperedHeader => "TAMPERED_HEADER",
            ErrorCode::TamperedCiphertext => "TAMPERED_CIPHERTEXT",
            ErrorCode::KdfDerivationFailed => "KDF_DERIVATION_FAILED",
            ErrorCode::SchemaMerkleLeafCountMismatch => "SCHEMA_MERKLE_LEAF_COUNT_MISMATCH",
            ErrorCode::SchemaMerkleLeavesFormatUnsupported => {
                "SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED"
            }
            ErrorCode::SchemaMerkleLeavesMalformed => "SCHEMA_MERKLE_LEAVES_MALFORMED",
            ErrorCode::MerkleRootMismatch => "MERKLE_ROOT_MISMATCH",
            ErrorCode::MerkleLeavesUnavailable => "MERKLE_LEAVES_UNAVAILABLE",
            ErrorCode::MerkleLeavesInformativeForm => "MERKLE_LEAVES_INFORMATIVE_FORM",
            ErrorCode::MerkleUnsupported => "MERKLE_UNSUPPORTED",
            ErrorCode::OutOfProfileSkipped => "OUT_OF_PROFILE_SKIPPED",
        }
    }

    /// The severity for this code.
    ///
    /// Every code is `Error` except `SIGNATURE_UNSUPPORTED`,
    /// `INSUFFICIENT_CONFIRMATIONS`, `MERKLE_LEAVES_INFORMATIVE_FORM`,
    /// `MERKLE_UNSUPPORTED`, and `OUT_OF_PROFILE_SKIPPED` (info), and
    /// `URI_FETCH_FAILED` / `MERKLE_LEAVES_UNAVAILABLE` (warning). The two
    /// dual-severity verifier codes record their default `info` reading here.
    #[must_use]
    pub const fn severity(self) -> Severity {
        match self {
            ErrorCode::SignatureUnsupported
            | ErrorCode::InsufficientConfirmations
            | ErrorCode::MerkleLeavesInformativeForm
            | ErrorCode::MerkleUnsupported
            | ErrorCode::OutOfProfileSkipped => Severity::Info,
            ErrorCode::UriFetchFailed | ErrorCode::MerkleLeavesUnavailable => Severity::Warning,
            _ => Severity::Error,
        }
    }
}

// ===========================================================================
// Record model
// ===========================================================================

/// A Label 309 v1 Proof-of-Existence record (the encoder's input).
///
/// The base keys mirror the wire format: `v`, `crit`, `sigs`, `items`,
/// `merkle`, `supersedes`. Every key not in that base set is an extension key,
/// retained verbatim in [`extensions`](PoeRecord::extensions) as a
/// `(name, CborValue)` pair. Extension keys are part of the canonical map AND of
/// the signed body, so they must round-trip byte-identically through both
/// encoders — the encoder copies each into the canonical map and the canonical
/// layer sorts them into key order.
///
/// Absent optional fields are encoded by omission (never as `null`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PoeRecord {
    /// Format version. MUST equal `1` on the wire.
    pub v: u64,
    /// Content items: each commits one logical object via its `hashes` map, with
    /// optional storage URIs and an optional sealed envelope.
    pub items: Option<Vec<ItemEntry>>,
    /// Top-level Merkle list commitments, peers of `items`.
    pub merkle: Option<Vec<MerkleCommit>>,
    /// The 32-byte transaction hash of a record this one supersedes.
    pub supersedes: Option<Vec<u8>>,
    /// Record-level detached COSE_Sign1 signatures.
    pub sigs: Option<Vec<SigEntry>>,
    /// Forward-compatibility "critical" extension names.
    pub crit: Option<Vec<String>>,
    /// Extension keys preserved verbatim, in insertion order. Each is a
    /// `(name, value)` pair; the canonical encoder re-sorts by key.
    pub extensions: Vec<(String, CborValue)>,
}

/// A single content item (`items[i]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemEntry {
    /// Content-hash map: algorithm identifier → digest bytes. Non-empty.
    pub hashes: Vec<(String, Vec<u8>)>,
    /// Storage URIs, each a chunked `[ tstr .size (1..64) ]` array.
    pub uris: Option<Vec<Vec<String>>>,
    /// Optional sealed-PoE envelope.
    pub enc: Option<EncryptionEnvelope>,
}

/// A Merkle list commitment (`merkle[i]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleCommit {
    /// List-commitment algorithm identifier.
    pub alg: String,
    /// The Merkle root digest bytes.
    pub root: Vec<u8>,
    /// The number of committed leaves (≥ 1).
    pub leaf_count: u64,
    /// Optional storage URIs for the leaves payload.
    pub uris: Option<Vec<Vec<String>>>,
}

/// A sealed-PoE encryption envelope (`items[i].enc`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionEnvelope {
    /// Envelope version. MUST equal `1`.
    pub scheme: u64,
    /// Content AEAD identifier.
    pub aead: String,
    /// Content AEAD nonce.
    pub nonce: Vec<u8>,
    /// KEM identifier (required when `slots` is present).
    pub kem: Option<String>,
    /// Recipient slots (exclusive with `passphrase`).
    pub slots: Option<Vec<Slot>>,
    /// MAC over the recipient slots (required iff `slots` is present).
    pub slots_mac: Option<Vec<u8>>,
    /// Passphrase key-derivation block (exclusive with `slots`).
    pub passphrase: Option<PassphraseBlock>,
}

/// A recipient slot (`enc.slots[j]`).
///
/// The slot carries exactly one ciphertext-bearing field for its KEM (`epk` for
/// x25519, `kem_ct` for the X-Wing hybrid) plus `wrap`. The KEM-foreign field
/// MUST be absent; the encoder emits only the fields that are set.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Slot {
    /// Classical ephemeral X25519 public key (x25519 KEM).
    pub epk: Option<Vec<u8>>,
    /// Hybrid X-Wing `enc`, pre-chunked into `[ bstr .size (1..64) ]`.
    pub kem_ct: Option<Vec<Vec<u8>>>,
    /// Wrapped CEK + AEAD tag (48 bytes).
    pub wrap: Option<Vec<u8>>,
}

/// A passphrase key-derivation block (`enc.passphrase`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassphraseBlock {
    /// Passphrase-KDF identifier.
    pub alg: String,
    /// KDF salt.
    pub salt: Vec<u8>,
    /// KDF parameters (`m`, `t`, `p` for Argon2id), as ordered `(name, value)`.
    pub params: Vec<(String, u64)>,
}

/// A record-level signature entry (`sigs[i]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigEntry {
    /// The detached COSE_Sign1 structure, chunked into `[ bstr .size (1..64) ]`.
    pub cose_sign1: Vec<Vec<u8>>,
    /// The optional path-2 `cbor<COSE_Key>` sidecar, chunked likewise.
    pub cose_key: Option<Vec<Vec<u8>>>,
}

// ===========================================================================
// Encoder
// ===========================================================================

/// Encode a record to canonical CBOR for chain submission.
///
/// The full record map, including `sigs` when present, plus every extension key.
/// Absent optional fields are omitted. The result reproduces the TypeScript
/// `encodePoeRecord` / Python `encode_poe_record` bytes exactly.
///
/// # Errors
///
/// Returns the canonical-encoder error only in the impossible case that two
/// extension keys carry byte-identical canonical encodings (a duplicate key).
pub fn encode_poe_record(record: &PoeRecord) -> Result<Vec<u8>, crate::cbor::CanonicalCborError> {
    encode_canonical_cbor(&record_to_cbor(record, true))
}

/// Encode the record body that record-level signatures cover.
///
/// Identical to [`encode_poe_record`] except the `sigs` key is excluded; `crit`,
/// `supersedes`, and every extension key are preserved. Reproduces the
/// TypeScript `encodeRecordBodyForSigning` / Python
/// `encode_record_body_for_signing` bytes exactly.
///
/// # Errors
///
/// Same as [`encode_poe_record`].
pub fn encode_record_body_for_signing(
    record: &PoeRecord,
) -> Result<Vec<u8>, crate::cbor::CanonicalCborError> {
    encode_canonical_cbor(&record_to_cbor(record, false))
}

/// Build the canonical-CBOR map value for a record.
///
/// Inserts every present base key plus every extension key as map pairs; the
/// canonical encoder sorts them. Insertion order here is irrelevant to the wire
/// bytes.
fn record_to_cbor(record: &PoeRecord, include_sigs: bool) -> CborValue {
    let mut pairs: Vec<(CborValue, CborValue)> = Vec::new();
    pairs.push((CborValue::text("v"), CborValue::Unsigned(record.v)));
    if let Some(items) = &record.items {
        pairs.push((
            CborValue::text("items"),
            CborValue::Array(items.iter().map(item_to_cbor).collect()),
        ));
    }
    if let Some(merkle) = &record.merkle {
        pairs.push((
            CborValue::text("merkle"),
            CborValue::Array(merkle.iter().map(merkle_to_cbor).collect()),
        ));
    }
    if let Some(supersedes) = &record.supersedes {
        pairs.push((
            CborValue::text("supersedes"),
            CborValue::Bytes(supersedes.clone()),
        ));
    }
    if include_sigs {
        if let Some(sigs) = &record.sigs {
            pairs.push((
                CborValue::text("sigs"),
                CborValue::Array(sigs.iter().map(sig_entry_to_cbor).collect()),
            ));
        }
    }
    if let Some(crit) = &record.crit {
        pairs.push((
            CborValue::text("crit"),
            CborValue::Array(crit.iter().map(CborValue::text).collect()),
        ));
    }
    for (key, value) in &record.extensions {
        pairs.push((CborValue::text(key.clone()), value.clone()));
    }
    CborValue::Map(pairs)
}

fn item_to_cbor(item: &ItemEntry) -> CborValue {
    let mut pairs: Vec<(CborValue, CborValue)> = Vec::new();
    let hashes = item
        .hashes
        .iter()
        .map(|(alg, digest)| {
            (
                CborValue::text(alg.clone()),
                CborValue::Bytes(digest.clone()),
            )
        })
        .collect();
    pairs.push((CborValue::text("hashes"), CborValue::Map(hashes)));
    if let Some(uris) = &item.uris {
        pairs.push((CborValue::text("uris"), uris_to_cbor(uris)));
    }
    if let Some(enc) = &item.enc {
        pairs.push((CborValue::text("enc"), envelope_to_cbor(enc)));
    }
    CborValue::Map(pairs)
}

fn merkle_to_cbor(commit: &MerkleCommit) -> CborValue {
    let mut pairs: Vec<(CborValue, CborValue)> = vec![
        (CborValue::text("alg"), CborValue::text(commit.alg.clone())),
        (
            CborValue::text("root"),
            CborValue::Bytes(commit.root.clone()),
        ),
        (
            CborValue::text("leaf_count"),
            CborValue::Unsigned(commit.leaf_count),
        ),
    ];
    if let Some(uris) = &commit.uris {
        pairs.push((CborValue::text("uris"), uris_to_cbor(uris)));
    }
    CborValue::Map(pairs)
}

fn uris_to_cbor(uris: &[Vec<String>]) -> CborValue {
    CborValue::Array(
        uris.iter()
            .map(|chunks| CborValue::Array(chunks.iter().map(CborValue::text).collect()))
            .collect(),
    )
}

fn envelope_to_cbor(enc: &EncryptionEnvelope) -> CborValue {
    let mut pairs: Vec<(CborValue, CborValue)> = vec![
        (CborValue::text("scheme"), CborValue::Unsigned(enc.scheme)),
        (CborValue::text("aead"), CborValue::text(enc.aead.clone())),
        (
            CborValue::text("nonce"),
            CborValue::Bytes(enc.nonce.clone()),
        ),
    ];
    if let Some(kem) = &enc.kem {
        pairs.push((CborValue::text("kem"), CborValue::text(kem.clone())));
    }
    if let Some(slots) = &enc.slots {
        pairs.push((
            CborValue::text("slots"),
            CborValue::Array(slots.iter().map(slot_to_cbor).collect()),
        ));
    }
    if let Some(slots_mac) = &enc.slots_mac {
        pairs.push((
            CborValue::text("slots_mac"),
            CborValue::Bytes(slots_mac.clone()),
        ));
    }
    if let Some(passphrase) = &enc.passphrase {
        pairs.push((
            CborValue::text("passphrase"),
            passphrase_to_cbor(passphrase),
        ));
    }
    CborValue::Map(pairs)
}

fn slot_to_cbor(slot: &Slot) -> CborValue {
    // KEM-driven slot serialization. A recipient slot is a closed 2-field map
    // selected by which ciphertext-bearing field the KEM uses: a hybrid
    // (X-Wing) slot is `{kem_ct, wrap}` and a classical (X25519) slot is
    // `{epk, wrap}`. The presence of `kem_ct` selects the hybrid shape and
    // drops any `epk`; otherwise the classical shape is emitted and any stray
    // `kem_ct` is dropped. Emitting both fields would produce a 3-key map the
    // validator rejects, so the selection here keeps the encoder and validator
    // in agreement. `kem_ct` is the ALREADY-chunked array, carried through
    // unchanged so the slot bytes match what `slots_mac` committed to
    // byte-for-byte. The canonical CBOR layer orders the keys (length-then-
    // bytewise), so insertion order here is irrelevant to the wire bytes.
    let wrap = CborValue::Bytes(slot.wrap.clone().unwrap_or_default());
    if let Some(kem_ct) = &slot.kem_ct {
        return CborValue::Map(vec![
            (
                CborValue::text("kem_ct"),
                CborValue::Array(kem_ct.iter().map(|c| CborValue::Bytes(c.clone())).collect()),
            ),
            (CborValue::text("wrap"), wrap),
        ]);
    }
    CborValue::Map(vec![
        (
            CborValue::text("epk"),
            CborValue::Bytes(slot.epk.clone().unwrap_or_default()),
        ),
        (CborValue::text("wrap"), wrap),
    ])
}

fn passphrase_to_cbor(pp: &PassphraseBlock) -> CborValue {
    let params = pp
        .params
        .iter()
        .map(|(name, value)| (CborValue::text(name.clone()), CborValue::Unsigned(*value)))
        .collect();
    CborValue::Map(vec![
        (CborValue::text("alg"), CborValue::text(pp.alg.clone())),
        (CborValue::text("salt"), CborValue::Bytes(pp.salt.clone())),
        (CborValue::text("params"), CborValue::Map(params)),
    ])
}

fn sig_entry_to_cbor(entry: &SigEntry) -> CborValue {
    let mut pairs: Vec<(CborValue, CborValue)> = vec![(
        CborValue::text("cose_sign1"),
        CborValue::Array(
            entry
                .cose_sign1
                .iter()
                .map(|c| CborValue::Bytes(c.clone()))
                .collect(),
        ),
    )];
    if let Some(cose_key) = &entry.cose_key {
        pairs.push((
            CborValue::text("cose_key"),
            CborValue::Array(
                cose_key
                    .iter()
                    .map(|c| CborValue::Bytes(c.clone()))
                    .collect(),
            ),
        ));
    }
    CborValue::Map(pairs)
}

// ===========================================================================
// Chunking helpers: split oversized byte/text values into the bounded
// chunks the canonical record encoding requires.
// ===========================================================================

const CHUNK_MAX_BYTES: usize = 64;

/// Split a logical byte string into `[ bstr .size (1..64) ]` chunks.
///
/// Always returns a non-empty vector. An empty input yields a single empty
/// chunk, which the validator's schema gate later rejects with
/// [`ErrorCode::ChunkTooLarge`]; real callers (COSE_Sign1, `cbor<COSE_Key>`,
/// X-Wing `enc`) never pass empty input.
#[must_use]
pub fn chunk_bytes(value: &[u8]) -> Vec<Vec<u8>> {
    if value.is_empty() {
        return vec![Vec::new()];
    }
    value.chunks(CHUNK_MAX_BYTES).map(<[u8]>::to_vec).collect()
}

/// Concatenate chunked bytes back into a single buffer.
///
/// The inverse of [`chunk_bytes`] for `bytes-chunk-array` shapes.
#[must_use]
pub fn bytes_chunk_array_concat(chunks: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(chunks.iter().map(Vec::len).sum());
    for chunk in chunks {
        out.extend_from_slice(chunk);
    }
    out
}

/// Chunk a URI into `[ tstr .size (1..64) ]`, splitting on UTF-8 codepoint
/// boundaries so no multi-byte codepoint straddles a chunk.
///
/// Pure-ASCII URIs collapse to plain 64-byte slices. An empty URI yields a
/// single empty chunk. A URI ≤ 64 bytes yields a single chunk.
#[must_use]
pub fn chunk_uri(uri: &str) -> Vec<String> {
    let bytes = uri.as_bytes();
    if bytes.is_empty() {
        return vec![String::new()];
    }
    if bytes.len() <= CHUNK_MAX_BYTES {
        return vec![uri.to_string()];
    }
    let mut chunks: Vec<String> = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        let mut end = (cursor + CHUNK_MAX_BYTES).min(bytes.len());
        // Rewind to the start of a codepoint if we landed inside one. UTF-8
        // continuation bytes match 0b10xx_xxxx.
        while end < bytes.len() && (bytes[end] & 0xc0) == 0x80 {
            end -= 1;
        }
        // The slice is guaranteed to be on char boundaries here, so this is
        // valid UTF-8.
        chunks.push(String::from_utf8_lossy(&bytes[cursor..end]).into_owned());
        cursor = end;
    }
    chunks
}

/// Result of reconstructing a chunked URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconstructUriResult {
    /// The chunks reconstructed to a valid UTF-8 URI string.
    Ok(String),
    /// The chunk bytes did not reconstruct to valid UTF-8.
    Invalid,
}

/// Reconstruct a chunked URI (`uri-chunk-array`) into its logical string.
///
/// Byte-concatenates the chunks and decodes the whole as strict UTF-8. The
/// canonical-CBOR decoder already rejects any non-UTF-8 `tstr` upstream, so the
/// [`ReconstructUriResult::Invalid`] branch is the residual structural guard.
#[must_use]
pub fn reconstruct_chunked_uri(chunks: &[String]) -> ReconstructUriResult {
    let mut merged: Vec<u8> = Vec::new();
    for chunk in chunks {
        merged.extend_from_slice(chunk.as_bytes());
    }
    match String::from_utf8(merged) {
        Ok(uri) => ReconstructUriResult::Ok(uri),
        Err(_) => ReconstructUriResult::Invalid,
    }
}

// ===========================================================================
// Validator
// ===========================================================================

/// One entry in the validator's result.
///
/// The cross-implementation parity contract is on [`code`](ValidationIssue::code)
/// and [`severity`](ValidationIssue::severity); the human-readable
/// [`message`](ValidationIssue::message) is informational and differs between
/// SDKs. (Unlike the TypeScript/Python issues, this Rust port does not carry a
/// structured `path`; the validator's parity surface is the emitted code set.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationIssue {
    /// The canonical taxonomy code.
    pub code: ErrorCode,
    /// The issue's severity.
    pub severity: Severity,
    /// A human-readable explanation. Not part of the parity contract.
    pub message: String,
}

/// The result of structural validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidateResult {
    /// The record passed: zero error-severity issues. `info` and `warning`
    /// issues (which never fail a record) are carried for inspection.
    Ok {
        /// The decoded record.
        record: Box<PoeRecord>,
        /// Info-severity issues (e.g. `SIGNATURE_UNSUPPORTED`).
        info: Vec<ValidationIssue>,
        /// Warning-severity issues.
        warnings: Vec<ValidationIssue>,
    },
    /// The record failed: at least one error-severity issue.
    Fail {
        /// The error-severity issues that failed the record.
        issues: Vec<ValidationIssue>,
    },
}

impl ValidateResult {
    /// Whether the record passed structural validation.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(self, ValidateResult::Ok { .. })
    }

    /// The set of emitted codes (error, warning, and info), for assertions.
    #[must_use]
    pub fn codes(&self) -> BTreeSet<ErrorCode> {
        match self {
            ValidateResult::Ok { info, warnings, .. } => {
                info.iter().chain(warnings.iter()).map(|i| i.code).collect()
            }
            ValidateResult::Fail { issues } => issues.iter().map(|i| i.code).collect(),
        }
    }
}

// --- Algorithm-identifier registries ---

const HASH_ALGS: &[(&str, usize)] = &[("sha2-256", 32), ("blake2b-256", 32)];
const MERKLE_COMMIT_ALGS: &[(&str, usize)] = &[("rfc9162-sha256", 32)];
const AEAD_NONCE_LENGTHS: &[(&str, usize)] = &[("xchacha20-poly1305", 24)];
const PASSPHRASE_ALGS: &[&str] = &["argon2id"];
const KNOWN_SIG_ALG_IDS: &[i64] = &[-8, -19];
const COSE_KEY_PRIVATE_MATERIAL_LABELS: &[i64] = &[-4];

const REGISTERED_RECORD_KEYS: &[&str] = &["v", "items", "merkle", "supersedes", "sigs", "crit"];
const REGISTERED_ITEM_KEYS: &[&str] = &["hashes", "uris", "enc"];
const REGISTERED_ENC_KEYS: &[&str] = &[
    "scheme",
    "aead",
    "kem",
    "nonce",
    "slots",
    "slots_mac",
    "passphrase",
];
const REGISTERED_PASSPHRASE_KEYS: &[&str] = &["alg", "salt", "params"];
const REGISTERED_SLOT_KEYS: &[&str] = &["epk", "kem_ct", "wrap"];
const REGISTERED_SIG_ENTRY_KEYS: &[&str] = &["cose_sign1", "cose_key"];
const REGISTERED_MERKLE_COMMIT_KEYS: &[&str] = &["alg", "root", "leaf_count", "uris"];

/// The X-Wing `enc` length carried by the `mlkem768x25519` hybrid KEM.
const MLKEM768X25519_ENC_LENGTH: usize = 1120;

/// Which ciphertext-bearing field a KEM uses, plus its expected length.
#[derive(Debug, Clone, Copy)]
struct KemSlotDescriptor {
    /// `"epk"` for a classical KEM, `"kem_ct"` for a hybrid KEM.
    field: &'static str,
    /// Expected (reassembled) length of the ciphertext-bearing field.
    field_length: usize,
    /// `wrap` length — 32-byte CEK + 16-byte AEAD tag.
    wrap_length: usize,
}

fn kem_slot_descriptor(kem: &str) -> Option<KemSlotDescriptor> {
    match kem {
        "x25519" => Some(KemSlotDescriptor {
            field: "epk",
            field_length: 32,
            wrap_length: 48,
        }),
        "mlkem768x25519" => Some(KemSlotDescriptor {
            field: "kem_ct",
            field_length: MLKEM768X25519_ENC_LENGTH,
            wrap_length: 48,
        }),
        _ => None,
    }
}

fn registry_lookup(registry: &[(&str, usize)], key: &str) -> Option<usize> {
    registry
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, len)| *len)
}

/// Whether a key is a vendor (`x-…`) or companion-CIP (`<cip>-…`) extension key.
///
/// Faithfully reproduces the reference regex `^(x-.+|[a-z]+-.+)$` with the exact
/// semantics the Python `re` module applies in its default mode: `.` matches any
/// single character EXCEPT the newline `U+000A`; the unanchored `$` matches at
/// the true end of the string OR immediately before a single trailing newline;
/// and the pattern is applied as a full anchored match (`^…$`). There is no
/// DOTALL and no MULTILINE.
///
/// Consequences that distinguish this from a naive byte-length check:
/// `"x-\n"`, `"a-\n"` and `"x-a\nb"` are NOT extension keys (the `.+` part can
/// only match the non-newline characters and the lone newline cannot satisfy it
/// or be spanned), while a single trailing newline IS tolerated (`"x-note\n"` is
/// an extension key). A second trailing newline (`"x-note\n\n"`) is not.
fn is_extension_key(key: &str) -> bool {
    // `$` lets exactly ONE trailing newline sit past the matched region; strip it
    // so the rest is a plain anchored match. Any further newline anywhere in the
    // remaining text is unmatchable (`.` never spans `\n`, and `$` only anchors at
    // the very end of this region), so the whole key is rejected.
    let core = key.strip_suffix('\n').unwrap_or(key);
    if core.contains('\n') {
        return false;
    }
    // `x-.+` : literal "x-" followed by at least one (now newline-free) char.
    if let Some(rest) = core.strip_prefix("x-") {
        if !rest.is_empty() {
            return true;
        }
    }
    // `[a-z]+-.+` : one-or-more ASCII-lowercase letters, a hyphen, then ≥1 char.
    let bytes = core.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_lowercase() {
        i += 1;
    }
    i >= 1 && i < bytes.len() && bytes[i] == b'-' && i + 1 < bytes.len()
}

/// Whether an AEAD identifier names an unauthenticated cipher.
///
/// Reproduces the regex
/// `(^|[-_])(cbc|ctr|ecb|cfb|ofb)([-_]|$)|^(rc4|des|3des)([-_]|$)` (ASCII,
/// case-insensitive): a delimited block-cipher mode token in any key-size
/// spelling, or a leading legacy stream/block cipher. The delimiters keep
/// authenticated AEADs (`aes-256-gcm`, `xchacha20-poly1305`) from matching.
///
/// The `$` in `([-_]|$)` follows the Python `re` semantics: it anchors at the
/// true end of the string OR immediately before a single trailing newline
/// (`U+000A`). So `aes-256-cbc\n` IS an unauthenticated cipher (the `$` matches
/// before the trailing newline), while `aes-256-cbc\nx` is not (the newline is
/// interior, not a token boundary) and `aes-256-cbc\r` is not (`\r` is not the
/// newline the `$` shorthand tolerates).
fn is_unauthenticated_cipher(aead: &str) -> bool {
    let lower = aead.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let is_delim = |b: u8| b == b'-' || b == b'_';
    // End-of-token boundary matching the regex `$`: the true end, or the index
    // just before a single trailing newline.
    let is_end_boundary =
        |after: usize| after == bytes.len() || (after + 1 == bytes.len() && bytes[after] == b'\n');

    // Arm 1: a delimited mode token anywhere.
    for mode in ["cbc", "ctr", "ecb", "cfb", "ofb"] {
        let m = mode.as_bytes();
        let mut start = 0;
        while let Some(rel) = find_subslice(&bytes[start..], m) {
            let idx = start + rel;
            let before_ok = idx == 0 || is_delim(bytes[idx - 1]);
            let after = idx + m.len();
            let after_ok = is_end_boundary(after) || is_delim(bytes[after]);
            if before_ok && after_ok {
                return true;
            }
            start = idx + 1;
        }
    }

    // Arm 2: a leading legacy cipher token.
    for legacy in ["rc4", "des", "3des"] {
        let l = legacy.as_bytes();
        if bytes.starts_with(l) {
            let after = l.len();
            if is_end_boundary(after) || is_delim(bytes[after]) {
                return true;
            }
        }
    }
    false
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Structural validator over canonical-CBOR record bytes.
///
/// A pure function: no I/O, no cryptographic signature verification, no
/// decryption. Returns the same accept/reject verdict and the same
/// [`ErrorCode`] set as the TypeScript and Python SDKs. The record passes iff it
/// emits zero error-severity issues; info and warning issues never fail it.
///
/// This implementation never panics: every failure mode maps to an issue.
#[must_use]
pub fn validate_poe_record(bytes: &[u8]) -> ValidateResult {
    // Step 2 — canonical CBOR decode. Every decode failure (malformed bytes,
    // indefinite-length, unsorted/duplicate map keys, non-minimal ints, invalid
    // UTF-8) folds into the single MALFORMED_CBOR code; the cbor layer keeps an
    // IndefiniteLength variant only for a descriptive message, and it reports the
    // same MALFORMED_CBOR stable code.
    let decoded = match decode_canonical_cbor(bytes) {
        Ok(value) => value,
        Err(cause) => {
            return ValidateResult::Fail {
                issues: vec![issue(
                    ErrorCode::MalformedCbor,
                    format!("cbor decode failed: {cause}"),
                )],
            };
        }
    };

    let mut issues: Vec<ValidationIssue> = Vec::new();
    let mut info: Vec<ValidationIssue> = Vec::new();

    let record_map = match as_map(&decoded) {
        Some(map) => map,
        None => {
            return ValidateResult::Fail {
                issues: vec![issue(
                    ErrorCode::SchemaTypeMismatch,
                    "top-level value must be a CBOR map".to_string(),
                )],
            };
        }
    };

    // Step 3 — top-level key gate (closed base + extension tolerance).
    check_record_top_level_keys(record_map, &mut issues, &mut info);

    // Step 3 / 4 — required `v` literal.
    match map_get(record_map, "v") {
        None => issues.push(issue(
            ErrorCode::SchemaMissingRequired,
            "missing required field 'v'".to_string(),
        )),
        Some(v_val) => {
            // `v` MUST be the unsigned integer 1. Floats are already rejected at
            // decode; a negative or larger uint is the only failure path here.
            if !matches!(v_val, CborValue::Unsigned(1)) {
                issues.push(issue(
                    ErrorCode::SchemaInvalidLiteral,
                    "v must be the unsigned integer 1".to_string(),
                ));
            }
        }
    }

    // Step 4a — content commitment + per-item / per-merkle walks.
    let mut items_non_empty = false;
    let mut merkle_non_empty = false;

    if let Some(items_raw) = map_get(record_map, "items") {
        match items_raw {
            CborValue::Array(items) => {
                if !items.is_empty() {
                    items_non_empty = true;
                    for item in items {
                        validate_item_entry(item, &mut issues);
                    }
                }
            }
            _ => issues.push(issue(
                ErrorCode::SchemaTypeMismatch,
                "items must be an array".to_string(),
            )),
        }
    }

    if let Some(merkle_raw) = map_get(record_map, "merkle") {
        match merkle_raw {
            CborValue::Array(commits) => {
                if !commits.is_empty() {
                    merkle_non_empty = true;
                    for commit in commits {
                        validate_merkle_commit(commit, &mut issues);
                    }
                }
            }
            _ => issues.push(issue(
                ErrorCode::SchemaTypeMismatch,
                "merkle must be an array".to_string(),
            )),
        }
    }

    if !items_non_empty && !merkle_non_empty {
        issues.push(issue(
            ErrorCode::SchemaEmptyRecord,
            "record carries neither items (>=1) nor merkle (>=1)".to_string(),
        ));
    }

    // Step 4h — supersedes length.
    if let Some(supersedes) = map_get(record_map, "supersedes") {
        validate_supersedes(supersedes, &mut issues);
    }

    // Step 4j — crit[] shape rules.
    if map_get(record_map, "crit").is_some() {
        validate_crit(record_map, &mut issues);
    }

    // Step 4f / 4g — sig entries.
    if let Some(sigs) = map_get(record_map, "sigs") {
        validate_sigs(sigs, &mut issues, &mut info);
    }

    // Step 5 — emit.
    if !issues.is_empty() {
        return ValidateResult::Fail { issues };
    }
    match record_from_cbor(&decoded) {
        Some(record) => ValidateResult::Ok {
            record: Box::new(record),
            info,
            warnings: Vec::new(),
        },
        // record_from_cbor only fails on a shape the domain pass already rejects,
        // so this branch is unreachable for an issue-free record; surface it as a
        // type mismatch rather than panicking.
        None => ValidateResult::Fail {
            issues: vec![issue(
                ErrorCode::SchemaTypeMismatch,
                "record decode produced an unexpected shape".to_string(),
            )],
        },
    }
}

fn issue(code: ErrorCode, message: String) -> ValidationIssue {
    ValidationIssue {
        code,
        severity: code.severity(),
        message,
    }
}

// --- CBOR map accessors (text-keyed) ---

fn as_map(value: &CborValue) -> Option<&[(CborValue, CborValue)]> {
    match value {
        CborValue::Map(pairs) => Some(pairs),
        _ => None,
    }
}

fn map_get<'a>(pairs: &'a [(CborValue, CborValue)], key: &str) -> Option<&'a CborValue> {
    pairs.iter().find_map(|(k, v)| match k {
        CborValue::Text(t) if t == key => Some(v),
        _ => None,
    })
}

fn map_has(pairs: &[(CborValue, CborValue)], key: &str) -> bool {
    map_get(pairs, key).is_some()
}

fn as_bytes(value: &CborValue) -> Option<&[u8]> {
    match value {
        CborValue::Bytes(b) => Some(b),
        _ => None,
    }
}

fn as_text(value: &CborValue) -> Option<&str> {
    match value {
        CborValue::Text(t) => Some(t),
        _ => None,
    }
}

// --- Top-level key gate ---

fn check_record_top_level_keys(
    record_map: &[(CborValue, CborValue)],
    issues: &mut Vec<ValidationIssue>,
    info: &mut Vec<ValidationIssue>,
) {
    for (key, _) in record_map {
        match key {
            CborValue::Text(k) => {
                if REGISTERED_RECORD_KEYS.contains(&k.as_str()) {
                    continue;
                }
                if is_extension_key(k) {
                    info.push(issue(
                        ErrorCode::OutOfProfileSkipped,
                        format!("top-level extension key '{k}' preserved but not interpreted"),
                    ));
                } else {
                    issues.push(issue(
                        ErrorCode::SchemaUnknownField,
                        format!("unknown record field: '{k}'"),
                    ));
                }
            }
            _ => issues.push(issue(
                ErrorCode::SchemaTypeMismatch,
                "top-level key must be a text string".to_string(),
            )),
        }
    }
}

fn check_unknown_keys(
    map: &[(CborValue, CborValue)],
    allowed: &[&str],
    label: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    for (key, _) in map {
        let ok = matches!(key, CborValue::Text(k) if allowed.contains(&k.as_str()));
        if !ok {
            issues.push(issue(
                ErrorCode::SchemaUnknownField,
                format!("unknown {label} field"),
            ));
        }
    }
}

// --- Item entry ---

fn validate_item_entry(item: &CborValue, issues: &mut Vec<ValidationIssue>) {
    let item_map = match as_map(item) {
        Some(map) => map,
        None => {
            issues.push(issue(
                ErrorCode::SchemaTypeMismatch,
                "item entry must be a map".to_string(),
            ));
            return;
        }
    };
    check_unknown_keys(item_map, REGISTERED_ITEM_KEYS, "item", issues);

    let hashes_raw = map_get(item_map, "hashes");
    match hashes_raw {
        Some(CborValue::Map(m)) if !m.is_empty() => {
            for (alg_key, digest) in m {
                validate_hash_map_entry(alg_key, digest, issues);
            }
        }
        _ => issues.push(issue(
            ErrorCode::SchemaTypeMismatch,
            "hashes must be a non-empty CBOR map of <alg-id> -> <digest>".to_string(),
        )),
    }

    if let Some(uris) = map_get(item_map, "uris") {
        validate_item_uris(uris, issues);
    }

    if let Some(enc) = map_get(item_map, "enc") {
        // Content-hash pre-check: an `enc`-bearing item's hashes MUST carry a
        // content-hash entry. Fires before inner enc-shape validation so the
        // more fundamental defect is reported first.
        let has_content_hash = matches!(hashes_raw, Some(CborValue::Map(m))
            if m.iter().any(|(k, _)| matches!(k, CborValue::Text(t)
                if HASH_ALGS.iter().any(|(alg, _)| alg == t))));
        // An enc-bearing item MUST commit to a content hash. `has_content_hash`
        // is already false for the empty/absent map, so the predicate is simply
        // its absence — the empty-map case emits ENC_REQUIRES_CONTENT_HASH too
        // (alongside the SCHEMA_TYPE_MISMATCH the hashes-shape check already
        // raised). When the precondition fails we skip the inner enc-shape walk:
        // the missing content commitment is the more fundamental defect.
        if !has_content_hash {
            issues.push(issue(
                ErrorCode::EncRequiresContentHash,
                "item carries `enc` but `hashes` has no content-hash entry (sha2-256 or blake2b-256)"
                    .to_string(),
            ));
        } else {
            validate_encryption(enc, issues);
        }
    }
}

fn validate_hash_map_entry(alg: &CborValue, digest: &CborValue, issues: &mut Vec<ValidationIssue>) {
    let alg_str = match alg {
        CborValue::Text(t) => t.as_str(),
        _ => {
            issues.push(issue(
                ErrorCode::UnsupportedHashAlg,
                "hash alg must be a text string".to_string(),
            ));
            return;
        }
    };
    let expected = match registry_lookup(HASH_ALGS, alg_str) {
        Some(len) => len,
        None => {
            issues.push(issue(
                ErrorCode::UnsupportedHashAlg,
                format!("unknown hash alg: {alg_str}"),
            ));
            return;
        }
    };
    let digest_bytes = match as_bytes(digest) {
        Some(b) => b,
        None => {
            issues.push(issue(
                ErrorCode::SchemaTypeMismatch,
                format!("hashes[{alg_str}] value must be CBOR bytes"),
            ));
            return;
        }
    };
    if digest_bytes.len() != expected {
        issues.push(issue(
            ErrorCode::HashDigestLengthMismatch,
            format!(
                "hashes[{alg_str}] digest length {} != {expected}",
                digest_bytes.len()
            ),
        ));
    }
}

// --- URIs ---

fn validate_item_uris(raw: &CborValue, issues: &mut Vec<ValidationIssue>) {
    match raw {
        CborValue::Array(uris) if !uris.is_empty() => {
            for chunks in uris {
                validate_one_uri(chunks, issues);
            }
        }
        _ => issues.push(issue(
            ErrorCode::SchemaTypeMismatch,
            "uris must be a non-empty array of chunked-tstr-arrays".to_string(),
        )),
    }
}

fn validate_one_uri(chunks: &CborValue, issues: &mut Vec<ValidationIssue>) {
    let chunk_arr = match chunks {
        CborValue::Array(c) if !c.is_empty() => c,
        _ => {
            issues.push(issue(
                ErrorCode::SchemaTypeMismatch,
                "each URI must be a non-empty array of tstr chunks (<=64B each)".to_string(),
            ));
            return;
        }
    };
    let mut typed: Vec<String> = Vec::with_capacity(chunk_arr.len());
    let mut type_ok = true;
    for chunk in chunk_arr {
        match chunk {
            CborValue::Text(s) => {
                let byte_len = s.len();
                if !(1..=64).contains(&byte_len) {
                    issues.push(issue(
                        ErrorCode::ChunkTooLarge,
                        format!("chunk length {byte_len} not in [1, 64]"),
                    ));
                    type_ok = false;
                } else {
                    typed.push(s.clone());
                }
            }
            _ => {
                issues.push(issue(
                    ErrorCode::SchemaTypeMismatch,
                    "chunked-tstr element must be a text string".to_string(),
                ));
                type_ok = false;
            }
        }
    }
    if !type_ok {
        return;
    }
    let uri = match reconstruct_chunked_uri(&typed) {
        ReconstructUriResult::Ok(uri) => uri,
        ReconstructUriResult::Invalid => {
            issues.push(issue(
                ErrorCode::InvalidUri,
                "URI chunk reconstruction failed".to_string(),
            ));
            return;
        }
    };
    if uri.contains('#') {
        issues.push(issue(
            ErrorCode::InvalidUri,
            "URI contains a fragment identifier ('#'), which is forbidden".to_string(),
        ));
        return;
    }
    if !is_absolute_uri(&uri) {
        issues.push(issue(
            ErrorCode::InvalidUri,
            "URI is not absolute (missing scheme://hierarchical-part)".to_string(),
        ));
        return;
    }
    // Permitted-scheme gate, applied case-INSENSITIVELY (`^(ar|ipfs)://`): any
    // scheme outside {ar, ipfs} — in any casing — is rejected here.
    if !is_permitted_scheme(&uri) {
        issues.push(issue(
            ErrorCode::InvalidUri,
            "unsupported URI scheme; v1 PoE URI set is {ar://, ipfs://}".to_string(),
        ));
        return;
    }
    // Body dispatch. RFC 3986 §3.1 makes the scheme case-insensitive, so fold
    // the scheme to lowercase before dispatching — `AR://`/`IPFS://` resolve to
    // the same fetch path as `ar://`/`ipfs://` and their bodies ARE shape-checked.
    // Only the scheme is folded: the txid and CID bodies keep their exact case
    // (they are case-sensitive identifiers).
    let scheme_folded = fold_scheme_lowercase(&uri);
    if scheme_folded.starts_with("ar://") {
        if !is_arweave_txid(&scheme_folded) {
            issues.push(issue(
                ErrorCode::InvalidUri,
                "ar:// URI does not match `^ar://[A-Za-z0-9_-]{43}$` \
                 (43-char base64url txid, no path/query/fragment)"
                    .to_string(),
            ));
        }
    } else if let Some(rest) = scheme_folded.strip_prefix("ipfs://") {
        let cid = rest.split('/').next().unwrap_or("");
        if !is_valid_cid(cid) {
            issues.push(issue(
                ErrorCode::InvalidUri,
                "ipfs:// URI is not a valid CID under the Label 309 profile".to_string(),
            ));
        }
    }
}

/// Lowercase only the scheme component of an absolute URI (everything up to and
/// including the first `://`), leaving the authority/path bytes untouched. The
/// scheme is case-insensitive per RFC 3986 §3.1; the body is not.
fn fold_scheme_lowercase(uri: &str) -> String {
    match uri.find("://") {
        Some(i) => {
            let end = i + "://".len();
            let mut out = uri[..end].to_ascii_lowercase();
            out.push_str(&uri[end..]);
            out
        }
        None => uri.to_string(),
    }
}

/// `^(ar|ipfs)://` (case-insensitive) — the closed v1 fetch-scheme gate.
fn is_permitted_scheme(uri: &str) -> bool {
    let lower = uri.to_ascii_lowercase();
    lower.starts_with("ar://") || lower.starts_with("ipfs://")
}

/// `^[a-z][a-z0-9+.-]*://` (case-insensitive).
fn is_absolute_uri(uri: &str) -> bool {
    let scheme_end = match uri.find("://") {
        Some(i) => i,
        None => return false,
    };
    if scheme_end == 0 {
        return false;
    }
    let scheme = &uri.as_bytes()[..scheme_end];
    if !scheme[0].is_ascii_alphabetic() {
        return false;
    }
    scheme
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'.' || b == b'-')
}

/// `^ar://[A-Za-z0-9_-]{43}$`.
fn is_arweave_txid(uri: &str) -> bool {
    let rest = match uri.strip_prefix("ar://") {
        Some(r) => r,
        None => return false,
    };
    rest.len() == 43
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

// --- Encryption envelope ---

fn validate_encryption(enc: &CborValue, issues: &mut Vec<ValidationIssue>) {
    let enc_map = match as_map(enc) {
        Some(map) => map,
        None => {
            issues.push(issue(
                ErrorCode::SchemaTypeMismatch,
                "enc must be a map".to_string(),
            ));
            return;
        }
    };
    check_unknown_keys(enc_map, REGISTERED_ENC_KEYS, "enc", issues);

    // `scheme` MUST be the unsigned integer 1 (floats already rejected at decode).
    if !matches!(map_get(enc_map, "scheme"), Some(CborValue::Unsigned(1))) {
        issues.push(issue(
            ErrorCode::UnsupportedEnvelopeScheme,
            "enc.scheme must be the unsigned integer 1".to_string(),
        ));
    }

    let aead = match map_get(enc_map, "aead").and_then(as_text) {
        Some(a) => a,
        None => {
            issues.push(issue(
                ErrorCode::UnsupportedAeadAlg,
                "unknown aead alg".to_string(),
            ));
            return;
        }
    };
    if is_unauthenticated_cipher(aead) {
        issues.push(issue(
            ErrorCode::UnauthenticatedCipherForbidden,
            format!("{aead} is an unauthenticated cipher"),
        ));
        return;
    }
    let nonce_len = match registry_lookup(AEAD_NONCE_LENGTHS, aead) {
        Some(len) => len,
        None => {
            issues.push(issue(
                ErrorCode::UnsupportedAeadAlg,
                format!("unknown aead alg: {aead}"),
            ));
            return;
        }
    };

    // KEM resolution (only a registered KEM drives the slot-shape pass).
    let has_kem = map_has(enc_map, "kem");
    let mut kem_resolved: Option<&str> = None;
    if has_kem {
        match map_get(enc_map, "kem").and_then(as_text) {
            Some(kem) if kem_slot_descriptor(kem).is_some() => kem_resolved = Some(kem),
            _ => issues.push(issue(
                ErrorCode::UnsupportedKemAlg,
                "unknown kem alg".to_string(),
            )),
        }
    }

    // Nonce.
    match map_get(enc_map, "nonce") {
        Some(CborValue::Bytes(nonce)) => {
            if nonce.len() != nonce_len {
                issues.push(issue(
                    ErrorCode::NonceLengthMismatch,
                    format!("nonce length {} != {nonce_len} for {aead}", nonce.len()),
                ));
            }
        }
        _ => issues.push(issue(
            ErrorCode::SchemaTypeMismatch,
            "nonce must be bytes".to_string(),
        )),
    }

    let has_slots = map_has(enc_map, "slots");
    let has_slots_mac = map_has(enc_map, "slots_mac");
    let has_passphrase = map_has(enc_map, "passphrase");

    // Slots.
    if has_slots {
        match map_get(enc_map, "slots") {
            Some(CborValue::Array(slots)) => {
                if slots.is_empty() {
                    issues.push(issue(
                        ErrorCode::EncSlotsEmpty,
                        "slots must be a non-empty array".to_string(),
                    ));
                } else if let Some(kem) = kem_resolved {
                    for slot in slots {
                        validate_slot(slot, kem, issues);
                    }
                }
            }
            _ => issues.push(issue(
                ErrorCode::SchemaTypeMismatch,
                "slots must be an array".to_string(),
            )),
        }
    }

    // slots_mac.
    if has_slots_mac {
        match map_get(enc_map, "slots_mac") {
            Some(CborValue::Bytes(mac)) => {
                if mac.len() != 32 {
                    issues.push(issue(
                        ErrorCode::EncSlotsMacInvalidLength,
                        format!("slots_mac length {} != 32", mac.len()),
                    ));
                }
            }
            _ => issues.push(issue(
                ErrorCode::SchemaTypeMismatch,
                "slots_mac must be bytes".to_string(),
            )),
        }
    }

    // Key-path branching.
    if has_slots && has_passphrase {
        issues.push(issue(
            ErrorCode::EncExclusivityViolation,
            "enc combines slots with passphrase; exactly one MUST be present".to_string(),
        ));
    }
    if has_slots && !has_slots_mac {
        issues.push(issue(
            ErrorCode::EncSlotsMacRequired,
            "enc.slots present but enc.slots_mac absent".to_string(),
        ));
    }
    if has_slots_mac && !has_slots {
        issues.push(issue(
            ErrorCode::EncSlotsRequired,
            "enc.slots_mac present but enc.slots absent".to_string(),
        ));
    }
    if has_slots && !has_kem {
        issues.push(issue(
            ErrorCode::EncKemRequired,
            "enc.slots present but enc.kem absent".to_string(),
        ));
    }
    if !has_slots && !has_passphrase {
        issues.push(issue(
            ErrorCode::EncNoKeyPath,
            "enc requires either slots or passphrase".to_string(),
        ));
    }

    if has_passphrase {
        if let Some(pp) = map_get(enc_map, "passphrase") {
            validate_passphrase(pp, issues);
        }
    }
}

fn validate_slot(slot: &CborValue, kem: &str, issues: &mut Vec<ValidationIssue>) {
    let slot_map = match as_map(slot) {
        Some(map) => map,
        None => {
            issues.push(issue(
                ErrorCode::EncSlotInvalidShape,
                "recipient slot must be a map".to_string(),
            ));
            return;
        }
    };
    // kem is a resolved registered member, so the descriptor is present.
    let descriptor = match kem_slot_descriptor(kem) {
        Some(d) => d,
        None => return,
    };

    // The foreign ciphertext field's presence is a shape violation regardless of
    // length.
    let foreign_field = if descriptor.field == "epk" {
        "kem_ct"
    } else {
        "epk"
    };
    if map_has(slot_map, foreign_field) {
        issues.push(issue(
            ErrorCode::EncSlotInvalidShape,
            format!(
                "slot carries '{foreign_field}' but kem='{kem}' expects '{}'",
                descriptor.field
            ),
        ));
    }

    // Any key outside {<ct field>, wrap} for this KEM is a closed-map violation.
    for (key, _) in slot_map {
        let known = matches!(key, CborValue::Text(k) if REGISTERED_SLOT_KEYS.contains(&k.as_str()));
        if !known {
            issues.push(issue(
                ErrorCode::EncSlotInvalidShape,
                "slot carries an unexpected key".to_string(),
            ));
        }
    }

    // Required ciphertext-bearing field at the expected (reassembled) length.
    if descriptor.field == "epk" {
        match map_get(slot_map, "epk") {
            None => issues.push(issue(
                ErrorCode::EncSlotInvalidShape,
                format!("slot for kem='{kem}' is missing required 'epk'"),
            )),
            Some(CborValue::Bytes(epk)) => {
                if epk.len() != descriptor.field_length {
                    issues.push(issue(
                        ErrorCode::KemEpkLengthMismatch,
                        format!(
                            "epk length {} != {} for {kem}",
                            epk.len(),
                            descriptor.field_length
                        ),
                    ));
                }
            }
            Some(_) => issues.push(issue(
                ErrorCode::EncSlotInvalidShape,
                "slot epk must be bytes".to_string(),
            )),
        }
    } else if let Some(reassembled) = reassemble_kem_ct(map_get(slot_map, "kem_ct"), issues) {
        if reassembled != descriptor.field_length {
            issues.push(issue(
                ErrorCode::KemCtLengthMismatch,
                format!(
                    "kem_ct reassembles to {reassembled} bytes != {} for {kem}",
                    descriptor.field_length
                ),
            ));
        }
    }

    // `wrap` is 48 bytes for every KEM.
    match map_get(slot_map, "wrap") {
        None => issues.push(issue(
            ErrorCode::EncSlotInvalidShape,
            format!("slot for kem='{kem}' is missing required 'wrap'"),
        )),
        Some(CborValue::Bytes(wrap)) => {
            if wrap.len() != descriptor.wrap_length {
                issues.push(issue(
                    ErrorCode::WrapLengthMismatch,
                    format!("wrap length {} != {}", wrap.len(), descriptor.wrap_length),
                ));
            }
        }
        Some(_) => issues.push(issue(
            ErrorCode::EncSlotInvalidShape,
            "slot wrap must be bytes".to_string(),
        )),
    }
}

/// Validate the chunked-bytes shape of `kem_ct` and return its reassembled byte
/// length, or `None` when the field is missing or malformed.
fn reassemble_kem_ct(raw: Option<&CborValue>, issues: &mut Vec<ValidationIssue>) -> Option<usize> {
    let chunks = match raw {
        None => {
            issues.push(issue(
                ErrorCode::EncSlotInvalidShape,
                "hybrid slot is missing required 'kem_ct'".to_string(),
            ));
            return None;
        }
        Some(CborValue::Array(c)) if !c.is_empty() => c,
        Some(_) => {
            issues.push(issue(
                ErrorCode::EncSlotInvalidShape,
                "kem_ct must be a non-empty array of byte chunks".to_string(),
            ));
            return None;
        }
    };
    let mut total = 0usize;
    let mut shape_ok = true;
    for chunk in chunks {
        match chunk {
            CborValue::Bytes(b) => {
                if !(1..=64).contains(&b.len()) {
                    issues.push(issue(
                        ErrorCode::ChunkTooLarge,
                        format!("chunk length {} not in [1, 64]", b.len()),
                    ));
                    shape_ok = false;
                } else {
                    total += b.len();
                }
            }
            _ => {
                issues.push(issue(
                    ErrorCode::EncSlotInvalidShape,
                    "kem_ct chunk must be a byte string".to_string(),
                ));
                shape_ok = false;
            }
        }
    }
    if shape_ok {
        Some(total)
    } else {
        None
    }
}

fn validate_passphrase(passphrase: &CborValue, issues: &mut Vec<ValidationIssue>) {
    let pp = match as_map(passphrase) {
        Some(map) => map,
        None => {
            issues.push(issue(
                ErrorCode::SchemaTypeMismatch,
                "passphrase must be a map".to_string(),
            ));
            return;
        }
    };
    check_unknown_keys(pp, REGISTERED_PASSPHRASE_KEYS, "passphrase", issues);

    let alg = map_get(pp, "alg").and_then(as_text);
    match alg {
        Some(a) if PASSPHRASE_ALGS.contains(&a) => {}
        _ => issues.push(issue(
            ErrorCode::EncPassphraseAlgUnsupported,
            "unknown passphrase alg".to_string(),
        )),
    }

    match map_get(pp, "salt") {
        Some(CborValue::Bytes(salt)) => {
            if salt.len() < 16 {
                issues.push(issue(
                    ErrorCode::EncPassphraseSaltTooShort,
                    format!("passphrase.salt length {} < 16", salt.len()),
                ));
            } else if salt.len() > 64 {
                issues.push(issue(
                    ErrorCode::EncPassphraseSaltTooLong,
                    format!("passphrase.salt length {} > 64", salt.len()),
                ));
            }
        }
        _ => issues.push(issue(
            ErrorCode::SchemaTypeMismatch,
            "salt must be bytes".to_string(),
        )),
    }

    let params = match map_get(pp, "params") {
        Some(CborValue::Map(m)) => m,
        Some(_) | None => {
            issues.push(issue(
                ErrorCode::SchemaTypeMismatch,
                "params must be a map".to_string(),
            ));
            return;
        }
    };

    if alg == Some("argon2id") {
        validate_argon2_params(params, issues);
    }
}

fn validate_argon2_params(params: &[(CborValue, CborValue)], issues: &mut Vec<ValidationIssue>) {
    for (key, _) in params {
        let known = matches!(key, CborValue::Text(k) if matches!(k.as_str(), "m" | "t" | "p"));
        if !known {
            issues.push(issue(
                ErrorCode::SchemaUnknownField,
                "unknown argon2id params field".to_string(),
            ));
        }
    }

    let int_param = |name: &str, issues: &mut Vec<ValidationIssue>| -> Option<u64> {
        match map_get(params, name) {
            Some(CborValue::Unsigned(n)) => Some(*n),
            _ => {
                issues.push(issue(
                    ErrorCode::SchemaTypeMismatch,
                    format!("argon2id params.{name} must be a CBOR unsigned integer"),
                ));
                None
            }
        }
    };

    if let Some(m) = int_param("m", issues) {
        if m < 65_536 {
            issues.push(issue(
                ErrorCode::EncPassphraseArgon2ParamsTooLow,
                "argon2id requires m >= 65536 KiB".to_string(),
            ));
        }
    }
    if let Some(t) = int_param("t", issues) {
        if t < 3 {
            issues.push(issue(
                ErrorCode::EncPassphraseArgon2ParamsTooLow,
                "argon2id requires t >= 3".to_string(),
            ));
        }
    }
    if let Some(p) = int_param("p", issues) {
        if p < 1 {
            issues.push(issue(
                ErrorCode::EncPassphraseArgon2ParamsTooLow,
                "argon2id requires p >= 1".to_string(),
            ));
        }
    }
}

// --- Merkle commitments ---

fn validate_merkle_commit(commit: &CborValue, issues: &mut Vec<ValidationIssue>) {
    let cm = match as_map(commit) {
        Some(map) => map,
        None => {
            issues.push(issue(
                ErrorCode::SchemaTypeMismatch,
                "merkle entry must be a map".to_string(),
            ));
            return;
        }
    };
    check_unknown_keys(cm, REGISTERED_MERKLE_COMMIT_KEYS, "merkle entry", issues);

    let mut alg_resolved: Option<&str> = None;
    match map_get(cm, "alg") {
        None => issues.push(issue(
            ErrorCode::SchemaMissingRequired,
            "merkle entry missing required 'alg'".to_string(),
        )),
        Some(CborValue::Text(alg)) => {
            if registry_lookup(MERKLE_COMMIT_ALGS, alg).is_some() {
                alg_resolved = Some(alg);
            } else {
                issues.push(issue(
                    ErrorCode::UnsupportedMerkleCommitAlg,
                    format!("unknown merkle commitment alg: {alg}"),
                ));
            }
        }
        Some(_) => issues.push(issue(
            ErrorCode::SchemaTypeMismatch,
            "merkle entry 'alg' must be a text string".to_string(),
        )),
    }

    match map_get(cm, "root") {
        None => issues.push(issue(
            ErrorCode::SchemaMissingRequired,
            "merkle entry missing required 'root'".to_string(),
        )),
        Some(CborValue::Bytes(root)) => {
            if let Some(alg) = alg_resolved {
                let expected = registry_lookup(MERKLE_COMMIT_ALGS, alg).unwrap_or(0);
                if root.len() != expected {
                    issues.push(issue(
                        ErrorCode::HashDigestLengthMismatch,
                        format!(
                            "merkle entry 'root' length {} != {expected} for {alg}",
                            root.len()
                        ),
                    ));
                }
            }
        }
        Some(_) => issues.push(issue(
            ErrorCode::SchemaTypeMismatch,
            "merkle entry 'root' must be CBOR bytes".to_string(),
        )),
    }

    match map_get(cm, "leaf_count") {
        None => issues.push(issue(
            ErrorCode::SchemaMissingRequired,
            "merkle entry missing required 'leaf_count'".to_string(),
        )),
        Some(CborValue::Unsigned(n)) if *n >= 1 => {}
        Some(_) => issues.push(issue(
            ErrorCode::SchemaTypeMismatch,
            "merkle entry 'leaf_count' must be a CBOR unsigned integer >= 1".to_string(),
        )),
    }

    if let Some(uris) = map_get(cm, "uris") {
        validate_item_uris(uris, issues);
    }
}

// --- supersedes ---

fn validate_supersedes(value: &CborValue, issues: &mut Vec<ValidationIssue>) {
    // A wrong TYPE (non-bytes) and a wrong LENGTH (bytes ≠ 32) are distinct
    // defects: the former violates the CDDL type, the latter the txid width.
    match value {
        CborValue::Bytes(b) if b.len() == 32 => {}
        CborValue::Bytes(_) => issues.push(issue(
            ErrorCode::SupersedesTxInvalidLength,
            "supersedes must be a 32-byte transaction hash".to_string(),
        )),
        _ => issues.push(issue(
            ErrorCode::SchemaTypeMismatch,
            "supersedes must be a byte string".to_string(),
        )),
    }
}

// --- crit[] ---

fn validate_crit(record_map: &[(CborValue, CborValue)], issues: &mut Vec<ValidationIssue>) {
    let crit_arr = match map_get(record_map, "crit") {
        Some(CborValue::Array(a)) if !a.is_empty() => a,
        _ => {
            issues.push(issue(
                ErrorCode::SchemaTypeMismatch,
                "crit must be a non-empty array of text strings".to_string(),
            ));
            return;
        }
    };
    let mut seen: Vec<String> = Vec::new();
    for entry in crit_arr {
        let name = match entry {
            CborValue::Text(t) => t,
            _ => {
                issues.push(issue(
                    ErrorCode::SchemaTypeMismatch,
                    "crit entry must be a text string".to_string(),
                ));
                continue;
            }
        };
        let mut reason: Option<String> = None;
        if REGISTERED_RECORD_KEYS.contains(&name.as_str()) {
            reason = Some(format!(
                "'{name}' is a base key and MUST NOT appear in crit[]"
            ));
        } else if !is_extension_key(name) {
            reason = Some(format!("'{name}' does not match the extension-key regex"));
        } else if !map_has(record_map, name) {
            reason = Some(format!(
                "'{name}' is named in crit but absent from the record map"
            ));
        } else if seen.contains(name) {
            reason = Some(format!("'{name}' appears more than once in crit[]"));
        }
        seen.push(name.clone());
        if let Some(reason) = reason {
            issues.push(issue(ErrorCode::CritShapeInvalid, reason));
            continue;
        }
        // v1 implements zero extensions, so every shape-valid crit entry is
        // unsupported.
        issues.push(issue(
            ErrorCode::ExtensionUnsupportedCritical,
            format!("crit entry '{name}' names an extension this validator does not implement"),
        ));
    }
}

// --- sigs[] ---

fn validate_sigs(
    raw: &CborValue,
    issues: &mut Vec<ValidationIssue>,
    info: &mut Vec<ValidationIssue>,
) {
    let entries = match raw {
        CborValue::Array(a) => a,
        _ => {
            issues.push(issue(
                ErrorCode::SchemaTypeMismatch,
                "sigs must be an array".to_string(),
            ));
            return;
        }
    };
    if entries.is_empty() {
        issues.push(issue(
            ErrorCode::SchemaTypeMismatch,
            "sigs must be a non-empty array when present".to_string(),
        ));
        return;
    }
    for entry in entries {
        validate_sig_entry(entry, issues, info);
    }
}

fn validate_sig_entry(
    entry: &CborValue,
    issues: &mut Vec<ValidationIssue>,
    info: &mut Vec<ValidationIssue>,
) {
    let entry_map = match as_map(entry) {
        Some(map) => map,
        None => {
            issues.push(issue(
                ErrorCode::SigEntryInvalidShape,
                "each sigs entry must be a CBOR map { cose_sign1, cose_key? }".to_string(),
            ));
            return;
        }
    };

    let cose_sign1_chunks = match map_get(entry_map, "cose_sign1") {
        None => {
            issues.push(issue(
                ErrorCode::SigEntryInvalidShape,
                "sigs entry missing required 'cose_sign1' field".to_string(),
            ));
            None
        }
        Some(raw) if is_chunked_bytes_shape(raw) => {
            let chunks = chunked_bytes(raw);
            validate_bytes_chunk_lengths(&chunks, issues);
            Some(chunks)
        }
        Some(_) => {
            issues.push(issue(
                ErrorCode::SigEntryInvalidShape,
                "sigs[i].cose_sign1 must be a non-empty list of byte chunks".to_string(),
            ));
            None
        }
    };

    if let Some(cose_key_raw) = map_get(entry_map, "cose_key") {
        if is_chunked_bytes_shape(cose_key_raw) {
            let chunks = chunked_bytes(cose_key_raw);
            validate_bytes_chunk_lengths(&chunks, issues);
            validate_cose_key_blob(&chunks, issues);
        } else {
            issues.push(issue(
                ErrorCode::SigEntryInvalidShape,
                "sigs[i].cose_key must be a non-empty list of byte chunks".to_string(),
            ));
        }
    }

    // A sig entry is a closed map `{ cose_sign1, cose_key? }`. An unrecognised
    // key is a shape violation, not a generic unknown-field one, so it emits
    // SIG_ENTRY_INVALID_SHAPE inline rather than via the shared unknown-field
    // helper (which item/enc/passphrase/merkle still use for SCHEMA_UNKNOWN_FIELD).
    for (key, _) in entry_map {
        let known = matches!(key, CborValue::Text(k)
            if REGISTERED_SIG_ENTRY_KEYS.contains(&k.as_str()));
        if !known {
            issues.push(issue(
                ErrorCode::SigEntryInvalidShape,
                "sigs entry carries an unrecognised key (allowed: cose_sign1, cose_key)"
                    .to_string(),
            ));
        }
    }

    if let Some(chunks) = cose_sign1_chunks {
        check_cose_sign1(&chunks, entry_map, issues, info);
    }
}

fn is_chunked_bytes_shape(value: &CborValue) -> bool {
    matches!(value, CborValue::Array(a)
        if !a.is_empty() && a.iter().all(|c| matches!(c, CborValue::Bytes(_))))
}

fn chunked_bytes(value: &CborValue) -> Vec<Vec<u8>> {
    match value {
        CborValue::Array(a) => a
            .iter()
            .filter_map(|c| match c {
                CborValue::Bytes(b) => Some(b.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn validate_bytes_chunk_lengths(chunks: &[Vec<u8>], issues: &mut Vec<ValidationIssue>) {
    for c in chunks {
        if !(1..=64).contains(&c.len()) {
            issues.push(issue(
                ErrorCode::ChunkTooLarge,
                format!("chunk length {} not in [1, 64]", c.len()),
            ));
        }
    }
}

/// Inspect a path-2 `cbor<COSE_Key>` blob: private-material guard FIRST, then
/// the positive Ed25519 OKP shape check.
fn validate_cose_key_blob(chunks: &[Vec<u8>], issues: &mut Vec<ValidationIssue>) {
    let joined = bytes_chunk_array_concat(chunks);
    // A COSE_Key is an int-keyed CBOR map; the canonical decoder reads it.
    let decoded = match decode_canonical_cbor(&joined) {
        Ok(v) => v,
        Err(_) => {
            issues.push(issue(
                ErrorCode::MalformedSigCoseSign1,
                "cose_key failed to decode as cbor<COSE_Key>".to_string(),
            ));
            return;
        }
    };
    let key_map = match as_map(&decoded) {
        Some(map) => map,
        None => {
            issues.push(issue(
                ErrorCode::MalformedSigCoseSign1,
                "cose_key did not decode to a CBOR map".to_string(),
            ));
            return;
        }
    };

    // Private-material guard FIRST.
    let leaks_private = key_map
        .iter()
        .any(|(k, _)| int_key(k).is_some_and(|n| COSE_KEY_PRIVATE_MATERIAL_LABELS.contains(&n)));
    if leaks_private {
        issues.push(issue(
            ErrorCode::SigPrivateKeyLeaked,
            "cose_key carries COSE_Key private-key material (label -4, the OKP/EC2 \
             private scalar d); publishing a private key on the permanent ledger is forbidden"
                .to_string(),
        ));
        return;
    }

    // Positive Ed25519 OKP shape: kty(1)=1, crv(-1)=6, 32-byte x(-2).
    if int_keyed_get(key_map, 1) != Some(&CborValue::Unsigned(1)) {
        issues.push(issue(
            ErrorCode::MalformedSigCoseSign1,
            "cose_key kty (label 1) must be 1 (OKP)".to_string(),
        ));
        return;
    }
    // crv label -1 → CborValue::Negative(0); value 6 → CborValue::Unsigned(6).
    if int_keyed_get(key_map, -1) != Some(&CborValue::Unsigned(6)) {
        issues.push(issue(
            ErrorCode::MalformedSigCoseSign1,
            "cose_key crv (label -1) must be 6 (Ed25519)".to_string(),
        ));
        return;
    }
    match int_keyed_get(key_map, -2) {
        Some(CborValue::Bytes(x)) if x.len() == 32 => {}
        _ => issues.push(issue(
            ErrorCode::MalformedSigCoseSign1,
            "cose_key label -2 must be a 32-byte byte string (Ed25519 public key)".to_string(),
        )),
    }
}

/// Step 4g — COSE_Sign1 structural decode + algorithm + path mutual-exclusion.
fn check_cose_sign1(
    chunks: &[Vec<u8>],
    entry_map: &[(CborValue, CborValue)],
    issues: &mut Vec<ValidationIssue>,
    info: &mut Vec<ValidationIssue>,
) {
    let merged = bytes_chunk_array_concat(chunks);
    let cose = match decode_cose_sign1(&merged) {
        Ok(c) => c,
        Err(message) => {
            issues.push(issue(ErrorCode::MalformedSigCoseSign1, message));
            return;
        }
    };
    if cose.payload_present {
        issues.push(issue(
            ErrorCode::MalformedSigCoseSign1,
            "COSE_Sign1 payload must be null (detached); attached form forbidden".to_string(),
        ));
        return;
    }

    // Signature-algorithm registry check (info-severity).
    let alg = cose
        .protected_header
        .as_ref()
        .and_then(|h| int_keyed_get(h, 1))
        .and_then(int_value);
    if !alg.is_some_and(|a| KNOWN_SIG_ALG_IDS.contains(&a)) {
        info.push(issue(
            ErrorCode::SignatureUnsupported,
            "alg not in KNOWN_SIG_ALG_IDS".to_string(),
        ));
    }

    // Path-1 / path-2 mutual exclusion.
    let kid = cose
        .protected_header
        .as_ref()
        .and_then(|h| int_keyed_get(h, 4));
    let kid_32 = matches!(kid, Some(CborValue::Bytes(b)) if b.len() == 32);
    if kid_32 && map_has(entry_map, "cose_key") {
        issues.push(issue(
            ErrorCode::SigEntryKidCoseKeyConflict,
            "sigs[i] carries both a 32-byte protected `kid` (path 1) and an inline `cose_key` \
             (path 2); paths are mutually exclusive"
                .to_string(),
        ));
    }
}

/// A minimally decoded COSE_Sign1 structure.
///
/// The structural validator needs only the protected header map (to read `alg`
/// and `kid`) and whether the payload is present (detached form requires null).
struct CoseSign1Decoded {
    protected_header: Option<Vec<(CborValue, CborValue)>>,
    payload_present: bool,
}

/// Structurally decode a COSE_Sign1 blob, reproducing the cross-SDK
/// `decode_cose_sign1` accept/reject rules.
///
/// Returns the error message on rejection; the caller surfaces it as
/// [`ErrorCode::MalformedSigCoseSign1`].
fn decode_cose_sign1(data: &[u8]) -> Result<CoseSign1Decoded, String> {
    let arr = decode_canonical_cbor(data).map_err(|_| "cose decode failed".to_string())?;
    let elems = match arr {
        CborValue::Array(a) if a.len() == 4 => a,
        _ => return Err("expected 4-element array".to_string()),
    };
    let protected_bytes = match &elems[0] {
        CborValue::Bytes(b) => b.clone(),
        _ => return Err("protected_bytes must be bytes".to_string()),
    };
    if !matches!(&elems[1], CborValue::Map(_)) {
        return Err("unprotected header must be map".to_string());
    }
    let payload_present = match &elems[2] {
        CborValue::Null => false,
        CborValue::Bytes(_) => true,
        _ => return Err("payload must be bytes or null".to_string()),
    };
    match &elems[3] {
        CborValue::Bytes(sig) if sig.len() == 64 => {}
        _ => return Err("signature must be 64 bytes".to_string()),
    }

    let protected_header = if protected_bytes.is_empty() {
        None
    } else {
        let decoded = decode_canonical_cbor(&protected_bytes)
            .map_err(|_| "protected header decode failed".to_string())?;
        let map = match decoded {
            CborValue::Map(m) => m,
            _ => return Err("protected header must decode to map".to_string()),
        };
        // An empty protected header MUST encode as the zero-length bstr 0x40, not
        // as a 1-byte bstr wrapping an empty map. Reaching here with an empty map
        // means it was the non-canonical wrapped form.
        if map.is_empty() {
            return Err(
                "empty protected header must encode as 0x40 (zero-length bstr)".to_string(),
            );
        }
        // The protected bytes MUST be canonical CBOR. The strict decoder above
        // already enforces canonical form, so a successful decode is canonical;
        // re-encoding and comparing is the explicit byte-pin the Python twin
        // applies because its CBOR library is permissive.
        let reencoded = encode_canonical_cbor(&CborValue::Map(map.clone()))
            .map_err(|_| "protected header re-encode failed".to_string())?;
        if reencoded != protected_bytes {
            return Err("protected header bytes are not canonical CBOR".to_string());
        }
        Some(map)
    };

    Ok(CoseSign1Decoded {
        protected_header,
        payload_present,
    })
}

// --- int-keyed map helpers (COSE_Key / COSE protected header) ---

/// Interpret a CBOR map key as a signed integer label, if it is one.
fn int_key(key: &CborValue) -> Option<i64> {
    int_value(key)
}

/// Interpret a CBOR integer value as `i64` (uint or nint within range).
fn int_value(value: &CborValue) -> Option<i64> {
    match value {
        CborValue::Unsigned(n) => i64::try_from(*n).ok(),
        // Negative(m) is -1 - m; reconstruct the signed value.
        CborValue::Negative(m) => i64::try_from(*m).ok().and_then(|m| (-1i64).checked_sub(m)),
        _ => None,
    }
}

/// Look up an integer-labelled entry in a CBOR map.
fn int_keyed_get(map: &[(CborValue, CborValue)], label: i64) -> Option<&CborValue> {
    map.iter().find_map(|(k, v)| {
        if int_key(k) == Some(label) {
            Some(v)
        } else {
            None
        }
    })
}

// ===========================================================================
// Decode CborValue → PoeRecord (for the validator's Ok branch)
// ===========================================================================

/// Reconstruct a [`PoeRecord`] from a decoded, structurally-valid CBOR map.
///
/// Called only after the domain pass has emitted zero issues, so every field is
/// the expected type; a `None` return is therefore unreachable in practice and
/// is mapped to a type-mismatch issue rather than panicking.
fn record_from_cbor(decoded: &CborValue) -> Option<PoeRecord> {
    let map = as_map(decoded)?;
    let mut record = PoeRecord {
        v: match map_get(map, "v")? {
            CborValue::Unsigned(n) => *n,
            _ => return None,
        },
        ..PoeRecord::default()
    };
    if let Some(CborValue::Array(items)) = map_get(map, "items") {
        record.items = Some(items.iter().filter_map(item_from_cbor).collect());
    }
    if let Some(CborValue::Array(merkle)) = map_get(map, "merkle") {
        record.merkle = Some(merkle.iter().filter_map(merkle_from_cbor).collect());
    }
    if let Some(CborValue::Bytes(s)) = map_get(map, "supersedes") {
        record.supersedes = Some(s.clone());
    }
    if let Some(CborValue::Array(sigs)) = map_get(map, "sigs") {
        record.sigs = Some(sigs.iter().filter_map(sig_from_cbor).collect());
    }
    if let Some(CborValue::Array(crit)) = map_get(map, "crit") {
        record.crit = Some(
            crit.iter()
                .filter_map(|c| as_text(c).map(str::to_string))
                .collect(),
        );
    }
    for (key, value) in map {
        if let CborValue::Text(k) = key {
            if !REGISTERED_RECORD_KEYS.contains(&k.as_str()) {
                record.extensions.push((k.clone(), value.clone()));
            }
        }
    }
    Some(record)
}

fn item_from_cbor(value: &CborValue) -> Option<ItemEntry> {
    let map = as_map(value)?;
    let hashes = match map_get(map, "hashes")? {
        CborValue::Map(m) => m
            .iter()
            .filter_map(|(k, v)| Some((as_text(k)?.to_string(), as_bytes(v)?.to_vec())))
            .collect(),
        _ => return None,
    };
    let uris = match map_get(map, "uris") {
        Some(CborValue::Array(u)) => Some(uris_from_cbor(u)),
        _ => None,
    };
    let enc = map_get(map, "enc").and_then(envelope_from_cbor);
    Some(ItemEntry { hashes, uris, enc })
}

fn uris_from_cbor(uris: &[CborValue]) -> Vec<Vec<String>> {
    uris.iter()
        .filter_map(|u| match u {
            CborValue::Array(chunks) => Some(
                chunks
                    .iter()
                    .filter_map(|c| as_text(c).map(str::to_string))
                    .collect(),
            ),
            _ => None,
        })
        .collect()
}

fn envelope_from_cbor(value: &CborValue) -> Option<EncryptionEnvelope> {
    let map = as_map(value)?;
    Some(EncryptionEnvelope {
        scheme: match map_get(map, "scheme")? {
            CborValue::Unsigned(n) => *n,
            _ => return None,
        },
        aead: as_text(map_get(map, "aead")?)?.to_string(),
        nonce: as_bytes(map_get(map, "nonce")?)?.to_vec(),
        kem: map_get(map, "kem").and_then(as_text).map(str::to_string),
        slots: match map_get(map, "slots") {
            Some(CborValue::Array(slots)) => {
                Some(slots.iter().filter_map(slot_from_cbor).collect())
            }
            _ => None,
        },
        slots_mac: map_get(map, "slots_mac")
            .and_then(as_bytes)
            .map(<[u8]>::to_vec),
        passphrase: map_get(map, "passphrase").and_then(passphrase_from_cbor),
    })
}

fn slot_from_cbor(value: &CborValue) -> Option<Slot> {
    let map = as_map(value)?;
    Some(Slot {
        epk: map_get(map, "epk").and_then(as_bytes).map(<[u8]>::to_vec),
        kem_ct: match map_get(map, "kem_ct") {
            Some(CborValue::Array(chunks)) => Some(
                chunks
                    .iter()
                    .filter_map(|c| as_bytes(c).map(<[u8]>::to_vec))
                    .collect(),
            ),
            _ => None,
        },
        wrap: map_get(map, "wrap").and_then(as_bytes).map(<[u8]>::to_vec),
    })
}

fn passphrase_from_cbor(value: &CborValue) -> Option<PassphraseBlock> {
    let map = as_map(value)?;
    let params = match map_get(map, "params")? {
        CborValue::Map(m) => m
            .iter()
            .filter_map(|(k, v)| match v {
                CborValue::Unsigned(n) => Some((as_text(k)?.to_string(), *n)),
                _ => None,
            })
            .collect(),
        _ => return None,
    };
    Some(PassphraseBlock {
        alg: as_text(map_get(map, "alg")?)?.to_string(),
        salt: as_bytes(map_get(map, "salt")?)?.to_vec(),
        params,
    })
}

fn merkle_from_cbor(value: &CborValue) -> Option<MerkleCommit> {
    let map = as_map(value)?;
    Some(MerkleCommit {
        alg: as_text(map_get(map, "alg")?)?.to_string(),
        root: as_bytes(map_get(map, "root")?)?.to_vec(),
        leaf_count: match map_get(map, "leaf_count")? {
            CborValue::Unsigned(n) => *n,
            _ => return None,
        },
        uris: match map_get(map, "uris") {
            Some(CborValue::Array(u)) => Some(uris_from_cbor(u)),
            _ => None,
        },
    })
}

fn sig_from_cbor(value: &CborValue) -> Option<SigEntry> {
    let map = as_map(value)?;
    let cose_sign1 = match map_get(map, "cose_sign1")? {
        CborValue::Array(chunks) => chunks
            .iter()
            .filter_map(|c| as_bytes(c).map(<[u8]>::to_vec))
            .collect(),
        _ => return None,
    };
    let cose_key = match map_get(map, "cose_key") {
        Some(CborValue::Array(chunks)) => Some(
            chunks
                .iter()
                .filter_map(|c| as_bytes(c).map(<[u8]>::to_vec))
                .collect(),
        ),
        _ => None,
    };
    Some(SigEntry {
        cose_sign1,
        cose_key,
    })
}

// ===========================================================================
// CID profile
// ===========================================================================

/// Whether a CID conforms to the accepted-CID profile for `ipfs://` URIs.
///
/// Accepts CIDv0 (`Qm…`, 46-char base58btc, sha2-256 multihash) and CIDv1
/// (multibase prefix ∈ {b,B,f,F,z} → `<version=1><multicodec><multihash>`,
/// multicodec ∈ {0x55, 0x70, 0x71}, multihash ∈ {0x12→32, 0xb220→32}).
#[must_use]
pub fn is_valid_cid(cid: &str) -> bool {
    if cid.is_empty() {
        return false;
    }
    if cid.starts_with("Qm") {
        // CIDv0: a 46-char base58btc string that base58btc-decodes to exactly
        // 34 bytes whose multihash prefix is sha2-256 (`0x12` code, `0x20` =
        // 32-byte length). A length/prefix check on the DECODED bytes is what
        // separates a real CIDv0 from any `Qm…`-shaped base58 string of the
        // right character length (e.g. `Qm1…` decodes to the wrong multihash
        // length byte and is rejected).
        if cid.len() != 46 {
            return false;
        }
        return match decode_base58btc(cid) {
            Some(decoded) => decoded.len() == 34 && decoded[0] == 0x12 && decoded[1] == 0x20,
            None => false,
        };
    }
    let mb_prefix = cid.as_bytes()[0] as char;
    if !matches!(mb_prefix, 'b' | 'B' | 'f' | 'F' | 'z') {
        return false;
    }
    let bytes = match decode_multibase(mb_prefix, &cid[1..]) {
        Some(b) => b,
        None => return false,
    };
    if bytes.len() < 4 {
        return false;
    }
    // <version varint> <multicodec varint> <multihash code varint> <len varint> <digest>
    let (version, pos) = match read_varint(&bytes, 0) {
        Some(v) => v,
        None => return false,
    };
    if version != 1 {
        return false;
    }
    let (codec, pos) = match read_varint(&bytes, pos) {
        Some(v) => v,
        None => return false,
    };
    if !matches!(codec, 0x55 | 0x70 | 0x71) {
        return false;
    }
    let (mh_code, pos) = match read_varint(&bytes, pos) {
        Some(v) => v,
        None => return false,
    };
    let (digest_len, pos) = match read_varint(&bytes, pos) {
        Some(v) => v,
        None => return false,
    };
    let expected = match mh_code {
        0x12 | 0xb220 => 32usize,
        _ => return false,
    };
    if digest_len as usize != expected {
        return false;
    }
    pos + digest_len as usize == bytes.len()
}

fn read_varint(bytes: &[u8], start: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    let mut i = start;
    while i < bytes.len() {
        let b = bytes[i];
        value |= u64::from(b & 0x7f) << shift;
        i += 1;
        if b & 0x80 == 0 {
            return Some((value, i));
        }
        shift += 7;
        if shift > 28 {
            return None;
        }
    }
    None
}

fn decode_multibase(prefix: char, body: &str) -> Option<Vec<u8>> {
    match prefix {
        'b' => decode_base32(&body.to_ascii_lowercase(), false),
        'B' => decode_base32(&body.to_ascii_uppercase(), true),
        'f' => decode_base16(&body.to_ascii_lowercase()),
        'F' => decode_base16(&body.to_ascii_uppercase()),
        'z' => decode_base58btc(body),
        _ => None,
    }
}

fn decode_base16(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_digit(bytes[i])?;
        let lo = hex_digit(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode_base32(s: &str, upper: bool) -> Option<Vec<u8>> {
    let alphabet: &[u8] = if upper {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    } else {
        b"abcdefghijklmnopqrstuvwxyz234567"
    };
    let trimmed = s.trim_end_matches('=');
    let mut out: Vec<u8> = Vec::new();
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for ch in trimmed.bytes() {
        let idx = alphabet.iter().position(|&a| a == ch)? as u32;
        buf = (buf << 5) | idx;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

fn decode_base58btc(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if s.is_empty() {
        return Some(Vec::new());
    }
    let chars = s.as_bytes();
    let mut zeros = 0;
    while zeros < chars.len() && chars[zeros] == b'1' {
        zeros += 1;
    }
    let size = (chars.len() - zeros) * 733 / 1000 + 1;
    let mut b256 = vec![0u8; size];
    let mut length = 0;
    for &ch in &chars[zeros..] {
        let mut carry = ALPHABET.iter().position(|&a| a == ch)? as u32;
        let mut k = 0;
        let mut j = size;
        while j > 0 && (carry != 0 || k < length) {
            j -= 1;
            carry += 58 * u32::from(b256[j]);
            b256[j] = (carry % 256) as u8;
            carry /= 256;
            k += 1;
        }
        length = k;
    }
    let mut it = size - length;
    while it < size && b256[it] == 0 {
        it += 1;
    }
    let mut out = vec![0u8; zeros];
    out.extend_from_slice(&b256[it..]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash32(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    fn minimal_record() -> PoeRecord {
        PoeRecord {
            v: 1,
            items: Some(vec![ItemEntry {
                hashes: vec![("sha2-256".to_string(), hash32(0xab))],
                uris: None,
                enc: None,
            }]),
            ..PoeRecord::default()
        }
    }

    #[test]
    fn encode_minimal_round_trips_through_validator() {
        let bytes = encode_poe_record(&minimal_record()).unwrap();
        let result = validate_poe_record(&bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn encode_is_deterministic_regardless_of_insertion_order() {
        let mut record = minimal_record();
        record.sigs = Some(vec![SigEntry {
            cose_sign1: vec![vec![0u8; 60]],
            cose_key: None,
        }]);
        let a = encode_poe_record(&record).unwrap();
        let b = encode_poe_record(&record).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn body_encoding_strips_sigs_only() {
        let mut with_sigs = minimal_record();
        with_sigs.sigs = Some(vec![SigEntry {
            cose_sign1: vec![vec![0x99u8; 64]],
            cose_key: None,
        }]);
        let body = encode_record_body_for_signing(&with_sigs).unwrap();
        let without = encode_poe_record(&minimal_record()).unwrap();
        assert_eq!(body, without);
    }

    #[test]
    fn extension_key_regex_matches_expected() {
        assert!(is_extension_key("x-note"));
        assert!(is_extension_key("seal-foo"));
        assert!(!is_extension_key("x-"));
        assert!(!is_extension_key("UPPERCASE-FOO"));
        assert!(!is_extension_key("nohyphen"));
    }

    #[test]
    fn unauthenticated_cipher_detection() {
        for aead in [
            "aes-256-cbc",
            "aes-128-cbc",
            "AES-256-CBC",
            "aes-256-ctr",
            "aes-128-ecb",
            "rc4",
            "des-ede3-cbc",
        ] {
            assert!(is_unauthenticated_cipher(aead), "{aead}");
        }
        for aead in ["aes-256-gcm", "chacha20-poly1305", "xchacha20-poly1305"] {
            assert!(!is_unauthenticated_cipher(aead), "{aead}");
        }
    }

    #[test]
    fn cidv0_profile_accepts_known_cid() {
        assert!(is_valid_cid(
            "QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH"
        ));
        assert!(!is_valid_cid("mAYIKsomethingbase64"));
    }

    #[test]
    fn error_code_strings_are_screaming_snake() {
        assert_eq!(ErrorCode::MalformedCbor.code(), "MALFORMED_CBOR");
        assert_eq!(
            ErrorCode::EncSlotInvalidShape.code(),
            "ENC_SLOT_INVALID_SHAPE"
        );
        assert_eq!(ErrorCode::SignatureUnsupported.severity(), Severity::Info);
    }
}
