//! Label 309 v1 Proof-of-Existence record wire format.
//!
//! This module is the wire-format core: the typed record model, the canonical
//! CBOR encoder, the structural validator, and the error-code catalogue. It is a
//! byte-parity twin of the TypeScript (`@cardanowall/poe-standard`) and Python
//! (`cardanowall.poe_standard`) implementations: it reproduces their exact
//! canonical-CBOR bytes and their exact validation verdicts against the same
//! shared cross-implementation conformance vectors.
//!
//! The two public encoders both emit RFC 8949 §4.2.1 canonical CBOR (the
//! [`crate::cbor`] layer does the deterministic ordering and shortest-form work):
//!
//! - [`encode_poe_record`] — the full record map, for chain submission.
//! - [`encode_record_body_for_signing`] — the same map with the `sigs` key
//!   dropped. These bytes are what record-level COSE_Sign1 signatures cover.
//!
//! Every logical byte string in the record body is a SINGLE CBOR byte string
//! and every URI is a SINGLE text string: `kem_ct` is one 1120-byte string,
//! `cose_sign1` / `cose_key` are single strings, and `uris[]` entries are plain
//! absolute URIs. The Cardano ledger's 64-byte metadata-string cap is satisfied
//! by the whole-body transport chunk array alone, which is reassembled before
//! the record body ever reaches this layer — record fields carry no chunk
//! wrappers of their own.
//!
//! [`validate_poe_record`] is a pure function over CBOR bytes that performs no
//! I/O, runs no cryptographic signature verification, and decrypts nothing. It
//! returns the same verdict, the same [`ErrorCode`] set, the same per-issue
//! severity, and the same sorted issue order as the other two SDKs for any
//! given `(bytes, options)` pair.

use std::collections::BTreeSet;

use crate::cbor::{decode_canonical_cbor, encode_canonical_cbor, CborValue};
// The verifier resource bounds the sealed-PoE unwrap layer enforces. Importing
// the same constants here, rather than re-declaring them, makes the structural
// validator and the unwrap layer default to identical thresholds. Both are
// deployment-pinned reference values, not wire fields — `ValidatorOptions`
// overrides them per deployment.
use crate::sealed_poe::{MAX_DECODED_ENVELOPE_BYTES, MAX_SLOTS};

// ===========================================================================
// Error-code catalogue
// ===========================================================================

/// One code from the Label 309 error-code registry.
///
/// The variants are declared in the registry's entry order, and that order is
/// load-bearing: issues sharing an identical path tie-break by registry
/// position ([`ErrorCode::registry_index`]), so every implementation sorts an
/// issue list identically.
///
/// Three layers emit these codes:
///
/// - **Part A** — the structural validator ([`validate_poe_record`]); these are
///   the only codes it ever emits.
/// - **carriage** — the pre-validator transport step that reassembles the
///   label-309 chunk array (`CHUNK_TOO_LARGE`).
/// - **Part B** — the public / recipient verifier (chain resolution, signature
///   verification, content fetch, decryption), included so downstream verifiers
///   dispatch on a single union.
///
/// Each variant's [`code`](ErrorCode::code) string matches the canonical
/// `SCREAMING_SNAKE_CASE` spelling byte-for-byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ErrorCode {
    /// Every canonical-CBOR decode failure: malformed/truncated bytes,
    /// indefinite-length encodings, non-canonical (unsorted) map keys, duplicate
    /// map keys, non-minimal integers, invalid UTF-8. One code, no finer grain.
    MalformedCbor,
    /// A field has the wrong CBOR type for its position (including a map
    /// carrying a non-text key where a text-keyed map is required).
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
    /// `merkle[i].leaf_count` is outside the pinned range `1 .. 2^32 - 1`.
    SchemaMerkleLeafCountInvalid,
    /// A URI is not a well-formed absolute `ar://` / `ipfs://` URI.
    InvalidUri,
    /// A transport chunk's byte length exceeds the ledger's 64-byte cap
    /// (carriage layer; never emitted by the structural validator).
    ChunkTooLarge,
    /// `enc.aead` names a forbidden unauthenticated cipher family member.
    UnauthenticatedCipherForbidden,
    /// `enc.aead` is not in the v1 content-format registry.
    UnsupportedAeadAlg,
    /// `enc.nonce` length does not match the content format's registered length.
    NonceLengthMismatch,
    /// `enc.scheme` is not a supported envelope scheme.
    UnsupportedEnvelopeScheme,
    /// The envelope uses identifiers this implementation does not support and
    /// degrades to the opaque reading. Dual severity: `info` in the public
    /// reading, `error` in the recipient role / strict sealed-crypto mode.
    EncUnsupported,
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
    /// A hybrid slot's `kem_ct` is not the X-Wing 1120-byte encapsulation.
    KemCtLengthMismatch,
    /// A slot's `wrap` is not 48 bytes.
    WrapLengthMismatch,
    /// `enc.slots_mac` is not 32 bytes.
    EncSlotsMacInvalidLength,
    /// `enc.slots` is present but `enc.slots_mac` is absent.
    EncSlotsMacRequired,
    /// `enc.slots_mac` is present but `enc.slots` is absent.
    EncSlotsRequired,
    /// Two slots in one `enc.slots` carry identical encapsulation material,
    /// breaking per-slot KEK uniqueness.
    EncSlotsDuplicateKemMaterial,
    /// `enc.slots` exceeds the slot-count resource bound.
    EncSlotsTooMany,
    /// The decoded `enc` envelope exceeds the byte-size resource bound.
    EncEnvelopeTooLarge,
    /// `enc` combines `passphrase` with the slots key path; the two are exclusive.
    EncExclusivityViolation,
    /// `enc` carries neither a `slots` nor a `passphrase` key path.
    EncNoKeyPath,
    /// An `enc`-bearing item's `hashes` carries no registered content-hash entry.
    EncRequiresContentHash,
    /// `enc.passphrase.alg` is not in the v1 passphrase-KDF registry.
    EncPassphraseAlgUnsupported,
    /// `enc.passphrase.salt` is shorter than 16 bytes.
    EncPassphraseSaltTooShort,
    /// `enc.passphrase.salt` is longer than 64 bytes.
    EncPassphraseSaltTooLong,
    /// An Argon2id parameter is below the v1 floor.
    EncPassphraseArgon2ParamsTooLow,
    /// An Argon2id parameter exceeds the deployment policy ceiling.
    EncPassphraseParamsExceedPolicy,
    /// A `sigs[i].cose_sign1` (or `cose_key`) blob is not a well-formed COSE
    /// structure, or the COSE_Sign1 carries an attached (non-null) payload.
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
    /// The referenced transaction could not be found on chain.
    TxNotFound,
    /// No chain/storage provider was reachable.
    ProviderUnavailable,
    /// The transaction bytes failed the tx-hash / auxiliary-data-hash binding.
    TxIntegrityMismatch,
    /// The transaction exists but carries no label-309 metadata.
    MetadataNotFound,
    /// The transaction has fewer confirmations than required; info-severity.
    InsufficientConfirmations,
    /// A record signature failed cryptographic verification.
    SignatureInvalid,
    /// A signer key could not be resolved.
    SignerKeyUnresolved,
    /// The signer wallet address did not match.
    WalletAddressMismatch,
    /// A URI target is outside the permitted fetch set.
    UriTargetForbidden,
    /// Fetched (attributable) bytes did not match the committed hash.
    UriIntegrityMismatch,
    /// Unattributable fetched bytes mismatched; warning-severity.
    UriProviderIntegrityMismatch,
    /// A URI fetch failed at runtime; warning-severity.
    UriFetchFailed,
    /// The committed content is unavailable.
    ContentUnavailable,
    /// The verifier's content-fetch budget was exhausted.
    ContentFetchLimitExceeded,
    /// The committed ciphertext is unavailable.
    CiphertextUnavailable,
    /// A service-independence invariant was violated.
    ServiceIndependenceViolation,
    /// Decryption input had the wrong shape for the envelope's key path.
    WrongDecryptionInputShape,
    /// The recipient key did not match any slot.
    WrongRecipientKey,
    /// The sealed header failed its authentication.
    TamperedHeader,
    /// The ciphertext failed its authentication.
    TamperedCiphertext,
    /// A key-derivation step failed.
    KdfDerivationFailed,
    /// A passphrase contained codepoints outside the pinned normalization profile.
    EncPassphraseUnnormalizable,
    /// A passphrase normalized to the empty string.
    EncPassphraseEmpty,
    /// A fetched leaves-list's leaf count did not match the commitment.
    SchemaMerkleLeafCountMismatch,
    /// A Merkle leaves payload used an unsupported format.
    SchemaMerkleLeavesFormatUnsupported,
    /// A Merkle leaves payload was structurally malformed.
    SchemaMerkleLeavesMalformed,
    /// A recomputed Merkle root did not match the committed root.
    MerkleRootMismatch,
    /// The Merkle leaves payload was unavailable; warning-severity (dual).
    MerkleLeavesUnavailable,
    /// A Merkle commitment used an unsupported feature; info-severity (dual).
    MerkleUnsupported,
    /// A check was skipped because it was outside the active verifier profile;
    /// info-severity (dual).
    OutOfProfileSkipped,
}

/// The severity classification of a validation issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    /// A fatal defect: any error-severity issue fails the record.
    Error,
    /// A non-fatal runtime anomaly that did not invalidate the record.
    Warning,
    /// A deliberate non-failing disposition.
    Info,
}

/// The layer that emits a code (the registry's `part` column).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCodePart {
    /// The structural validator.
    A,
    /// The verifier layer.
    B,
    /// The transport (chunk-array) reassembly step.
    Carriage,
}

/// The complete error-code registry, in canonical entry order.
pub const ERROR_CODES: &[ErrorCode] = &[
    ErrorCode::MalformedCbor,
    ErrorCode::SchemaTypeMismatch,
    ErrorCode::SchemaMissingRequired,
    ErrorCode::SchemaUnknownField,
    ErrorCode::SchemaInvalidLiteral,
    ErrorCode::SchemaEmptyRecord,
    ErrorCode::HashDigestLengthMismatch,
    ErrorCode::UnsupportedHashAlg,
    ErrorCode::UnsupportedMerkleCommitAlg,
    ErrorCode::SchemaMerkleLeafCountInvalid,
    ErrorCode::InvalidUri,
    ErrorCode::ChunkTooLarge,
    ErrorCode::UnauthenticatedCipherForbidden,
    ErrorCode::UnsupportedAeadAlg,
    ErrorCode::NonceLengthMismatch,
    ErrorCode::UnsupportedEnvelopeScheme,
    ErrorCode::EncUnsupported,
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
    ErrorCode::EncSlotsDuplicateKemMaterial,
    ErrorCode::EncSlotsTooMany,
    ErrorCode::EncEnvelopeTooLarge,
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
    ErrorCode::TxNotFound,
    ErrorCode::ProviderUnavailable,
    ErrorCode::TxIntegrityMismatch,
    ErrorCode::MetadataNotFound,
    ErrorCode::InsufficientConfirmations,
    ErrorCode::SignatureInvalid,
    ErrorCode::SignerKeyUnresolved,
    ErrorCode::WalletAddressMismatch,
    ErrorCode::UriTargetForbidden,
    ErrorCode::UriIntegrityMismatch,
    ErrorCode::UriProviderIntegrityMismatch,
    ErrorCode::UriFetchFailed,
    ErrorCode::ContentUnavailable,
    ErrorCode::ContentFetchLimitExceeded,
    ErrorCode::CiphertextUnavailable,
    ErrorCode::ServiceIndependenceViolation,
    ErrorCode::WrongDecryptionInputShape,
    ErrorCode::WrongRecipientKey,
    ErrorCode::TamperedHeader,
    ErrorCode::TamperedCiphertext,
    ErrorCode::KdfDerivationFailed,
    ErrorCode::EncPassphraseUnnormalizable,
    ErrorCode::EncPassphraseEmpty,
    ErrorCode::SchemaMerkleLeafCountMismatch,
    ErrorCode::SchemaMerkleLeavesFormatUnsupported,
    ErrorCode::SchemaMerkleLeavesMalformed,
    ErrorCode::MerkleRootMismatch,
    ErrorCode::MerkleLeavesUnavailable,
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
            ErrorCode::SchemaMerkleLeafCountInvalid => "SCHEMA_MERKLE_LEAF_COUNT_INVALID",
            ErrorCode::InvalidUri => "INVALID_URI",
            ErrorCode::ChunkTooLarge => "CHUNK_TOO_LARGE",
            ErrorCode::UnauthenticatedCipherForbidden => "UNAUTHENTICATED_CIPHER_FORBIDDEN",
            ErrorCode::UnsupportedAeadAlg => "UNSUPPORTED_AEAD_ALG",
            ErrorCode::NonceLengthMismatch => "NONCE_LENGTH_MISMATCH",
            ErrorCode::UnsupportedEnvelopeScheme => "UNSUPPORTED_ENVELOPE_SCHEME",
            ErrorCode::EncUnsupported => "ENC_UNSUPPORTED",
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
            ErrorCode::EncSlotsDuplicateKemMaterial => "ENC_SLOTS_DUPLICATE_KEM_MATERIAL",
            ErrorCode::EncSlotsTooMany => "ENC_SLOTS_TOO_MANY",
            ErrorCode::EncEnvelopeTooLarge => "ENC_ENVELOPE_TOO_LARGE",
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
            ErrorCode::TxNotFound => "TX_NOT_FOUND",
            ErrorCode::ProviderUnavailable => "PROVIDER_UNAVAILABLE",
            ErrorCode::TxIntegrityMismatch => "TX_INTEGRITY_MISMATCH",
            ErrorCode::MetadataNotFound => "METADATA_NOT_FOUND",
            ErrorCode::InsufficientConfirmations => "INSUFFICIENT_CONFIRMATIONS",
            ErrorCode::SignatureInvalid => "SIGNATURE_INVALID",
            ErrorCode::SignerKeyUnresolved => "SIGNER_KEY_UNRESOLVED",
            ErrorCode::WalletAddressMismatch => "WALLET_ADDRESS_MISMATCH",
            ErrorCode::UriTargetForbidden => "URI_TARGET_FORBIDDEN",
            ErrorCode::UriIntegrityMismatch => "URI_INTEGRITY_MISMATCH",
            ErrorCode::UriProviderIntegrityMismatch => "URI_PROVIDER_INTEGRITY_MISMATCH",
            ErrorCode::UriFetchFailed => "URI_FETCH_FAILED",
            ErrorCode::ContentUnavailable => "CONTENT_UNAVAILABLE",
            ErrorCode::ContentFetchLimitExceeded => "CONTENT_FETCH_LIMIT_EXCEEDED",
            ErrorCode::CiphertextUnavailable => "CIPHERTEXT_UNAVAILABLE",
            ErrorCode::ServiceIndependenceViolation => "SERVICE_INDEPENDENCE_VIOLATION",
            ErrorCode::WrongDecryptionInputShape => "WRONG_DECRYPTION_INPUT_SHAPE",
            ErrorCode::WrongRecipientKey => "WRONG_RECIPIENT_KEY",
            ErrorCode::TamperedHeader => "TAMPERED_HEADER",
            ErrorCode::TamperedCiphertext => "TAMPERED_CIPHERTEXT",
            ErrorCode::KdfDerivationFailed => "KDF_DERIVATION_FAILED",
            ErrorCode::EncPassphraseUnnormalizable => "ENC_PASSPHRASE_UNNORMALIZABLE",
            ErrorCode::EncPassphraseEmpty => "ENC_PASSPHRASE_EMPTY",
            ErrorCode::SchemaMerkleLeafCountMismatch => "SCHEMA_MERKLE_LEAF_COUNT_MISMATCH",
            ErrorCode::SchemaMerkleLeavesFormatUnsupported => {
                "SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED"
            }
            ErrorCode::SchemaMerkleLeavesMalformed => "SCHEMA_MERKLE_LEAVES_MALFORMED",
            ErrorCode::MerkleRootMismatch => "MERKLE_ROOT_MISMATCH",
            ErrorCode::MerkleLeavesUnavailable => "MERKLE_LEAVES_UNAVAILABLE",
            ErrorCode::MerkleUnsupported => "MERKLE_UNSUPPORTED",
            ErrorCode::OutOfProfileSkipped => "OUT_OF_PROFILE_SKIPPED",
        }
    }

    /// The default severity for this code.
    ///
    /// The four dual-severity codes ([`is_dual_severity`](Self::is_dual_severity))
    /// record their default reading here; a promoting context escalates them to
    /// [`Severity::Error`] (the validator does this for `ENC_UNSUPPORTED` under
    /// the recipient role).
    #[must_use]
    pub const fn severity(self) -> Severity {
        match self {
            ErrorCode::EncUnsupported
            | ErrorCode::SignatureUnsupported
            | ErrorCode::InsufficientConfirmations
            | ErrorCode::MerkleUnsupported
            | ErrorCode::OutOfProfileSkipped => Severity::Info,
            ErrorCode::UriProviderIntegrityMismatch
            | ErrorCode::UriFetchFailed
            | ErrorCode::MerkleLeavesUnavailable => Severity::Warning,
            _ => Severity::Error,
        }
    }

    /// The emitting layer (the registry's `part` column).
    #[must_use]
    pub const fn part(self) -> ErrorCodePart {
        match self {
            ErrorCode::ChunkTooLarge => ErrorCodePart::Carriage,
            ErrorCode::MalformedCbor
            | ErrorCode::SchemaTypeMismatch
            | ErrorCode::SchemaMissingRequired
            | ErrorCode::SchemaUnknownField
            | ErrorCode::SchemaInvalidLiteral
            | ErrorCode::SchemaEmptyRecord
            | ErrorCode::HashDigestLengthMismatch
            | ErrorCode::UnsupportedHashAlg
            | ErrorCode::UnsupportedMerkleCommitAlg
            | ErrorCode::SchemaMerkleLeafCountInvalid
            | ErrorCode::InvalidUri
            | ErrorCode::UnauthenticatedCipherForbidden
            | ErrorCode::UnsupportedAeadAlg
            | ErrorCode::NonceLengthMismatch
            | ErrorCode::UnsupportedEnvelopeScheme
            | ErrorCode::EncUnsupported
            | ErrorCode::EncSlotsEmpty
            | ErrorCode::EncSlotInvalidShape
            | ErrorCode::UnsupportedKemAlg
            | ErrorCode::EncKemRequired
            | ErrorCode::KemEpkLengthMismatch
            | ErrorCode::KemCtLengthMismatch
            | ErrorCode::WrapLengthMismatch
            | ErrorCode::EncSlotsMacInvalidLength
            | ErrorCode::EncSlotsMacRequired
            | ErrorCode::EncSlotsRequired
            | ErrorCode::EncSlotsDuplicateKemMaterial
            | ErrorCode::EncSlotsTooMany
            | ErrorCode::EncEnvelopeTooLarge
            | ErrorCode::EncExclusivityViolation
            | ErrorCode::EncNoKeyPath
            | ErrorCode::EncRequiresContentHash
            | ErrorCode::EncPassphraseAlgUnsupported
            | ErrorCode::EncPassphraseSaltTooShort
            | ErrorCode::EncPassphraseSaltTooLong
            | ErrorCode::EncPassphraseArgon2ParamsTooLow
            | ErrorCode::EncPassphraseParamsExceedPolicy
            | ErrorCode::MalformedSigCoseSign1
            | ErrorCode::SignatureUnsupported
            | ErrorCode::SigEntryInvalidShape
            | ErrorCode::SigEntryKidCoseKeyConflict
            | ErrorCode::SigPrivateKeyLeaked
            | ErrorCode::SupersedesTxInvalidLength
            | ErrorCode::ExtensionUnsupportedCritical
            | ErrorCode::CritShapeInvalid => ErrorCodePart::A,
            _ => ErrorCodePart::B,
        }
    }

    /// Whether this code carries context-dependent (dual) severity.
    #[must_use]
    pub const fn is_dual_severity(self) -> bool {
        matches!(
            self,
            ErrorCode::EncUnsupported
                | ErrorCode::MerkleLeavesUnavailable
                | ErrorCode::MerkleUnsupported
                | ErrorCode::OutOfProfileSkipped
        )
    }

    /// The position of this code in the canonical registry.
    ///
    /// Issues carrying an identical path are ordered by this index, so every
    /// implementation sorts an issue list identically.
    #[must_use]
    pub const fn registry_index(self) -> usize {
        self as usize
    }
}

/// The Part A (structural-validator) codes, in registry order.
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
    ErrorCode::SchemaMerkleLeafCountInvalid,
    ErrorCode::InvalidUri,
    ErrorCode::UnauthenticatedCipherForbidden,
    ErrorCode::UnsupportedAeadAlg,
    ErrorCode::NonceLengthMismatch,
    ErrorCode::UnsupportedEnvelopeScheme,
    ErrorCode::EncUnsupported,
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
    ErrorCode::EncSlotsDuplicateKemMaterial,
    ErrorCode::EncSlotsTooMany,
    ErrorCode::EncEnvelopeTooLarge,
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

/// The carriage (transport) codes, in registry order.
pub const CARRIAGE_ERROR_CODES: &[ErrorCode] = &[ErrorCode::ChunkTooLarge];

/// The Part B (verifier-layer) codes, in registry order.
///
/// Included so a downstream verifier can dispatch on the single [`ErrorCode`]
/// union; the structural validator never emits these.
pub const VERIFIER_ERROR_CODES: &[ErrorCode] = &[
    ErrorCode::TxNotFound,
    ErrorCode::ProviderUnavailable,
    ErrorCode::TxIntegrityMismatch,
    ErrorCode::MetadataNotFound,
    ErrorCode::InsufficientConfirmations,
    ErrorCode::SignatureInvalid,
    ErrorCode::SignerKeyUnresolved,
    ErrorCode::WalletAddressMismatch,
    ErrorCode::UriTargetForbidden,
    ErrorCode::UriIntegrityMismatch,
    ErrorCode::UriProviderIntegrityMismatch,
    ErrorCode::UriFetchFailed,
    ErrorCode::ContentUnavailable,
    ErrorCode::ContentFetchLimitExceeded,
    ErrorCode::CiphertextUnavailable,
    ErrorCode::ServiceIndependenceViolation,
    ErrorCode::WrongDecryptionInputShape,
    ErrorCode::WrongRecipientKey,
    ErrorCode::TamperedHeader,
    ErrorCode::TamperedCiphertext,
    ErrorCode::KdfDerivationFailed,
    ErrorCode::EncPassphraseUnnormalizable,
    ErrorCode::EncPassphraseEmpty,
    ErrorCode::SchemaMerkleLeafCountMismatch,
    ErrorCode::SchemaMerkleLeavesFormatUnsupported,
    ErrorCode::SchemaMerkleLeavesMalformed,
    ErrorCode::MerkleRootMismatch,
    ErrorCode::MerkleLeavesUnavailable,
    ErrorCode::MerkleUnsupported,
    ErrorCode::OutOfProfileSkipped,
];

// ===========================================================================
// Record model
// ===========================================================================

/// A Label 309 v1 Proof-of-Existence record (the encoder's input).
///
/// The base keys mirror the wire format: `v`, `items`, `merkle`, `supersedes`,
/// `sigs`, `crit`. Every key not in that base set is an extension key, retained
/// verbatim in [`extensions`](PoeRecord::extensions) as a `(name, CborValue)`
/// pair. Extension keys are part of the canonical map AND of the signed body,
/// so they round-trip byte-identically through both encoders — the canonical
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
    /// Storage URIs, each one absolute URI in a single text string.
    pub uris: Option<Vec<String>>,
    /// Optional encryption envelope.
    pub enc: Option<EncryptionEnvelope>,
}

/// A Merkle list commitment (`merkle[i]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleCommit {
    /// List-commitment algorithm identifier.
    pub alg: String,
    /// The Merkle root digest bytes.
    pub root: Vec<u8>,
    /// The number of committed leaves (`1 .. 2^32 - 1`).
    pub leaf_count: u64,
    /// Optional storage URIs for the leaves payload.
    pub uris: Option<Vec<String>>,
}

/// The `items[i].enc` value: a choice between the typed scheme-1 envelope and
/// the opaque reading.
///
/// Mirrors the grammar's `enc = enc-scheme-1 / enc-opaque`. The opaque arm
/// preserves an envelope under identifiers this implementation does not support
/// verbatim, so an accepted record re-encodes byte-identically regardless of
/// which reading applied. Producers construct [`Scheme1`](Self::Scheme1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptionEnvelope {
    /// The typed scheme-1 envelope this revision defines.
    Scheme1(EncScheme1),
    /// An envelope under unsupported identifiers, preserved as bounded CBOR
    /// metadata. A verifier escape hatch, never a producer surface.
    Opaque(CborValue),
}

/// The typed scheme-1 encryption envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncScheme1 {
    /// Envelope scheme. MUST equal `1`.
    pub scheme: u64,
    /// Content-format (AEAD) identifier.
    pub aead: String,
    /// The record-unique content nonce.
    pub nonce: Vec<u8>,
    /// KEM identifier (required when `slots` is present).
    pub kem: Option<String>,
    /// Recipient slots (exclusive with `passphrase`).
    pub slots: Option<Vec<Slot>>,
    /// MAC over the recipient slot set (required iff `slots` is present).
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
    /// Classical ephemeral X25519 public key (x25519 KEM; 32 bytes).
    pub epk: Option<Vec<u8>>,
    /// Hybrid X-Wing encapsulation (mlkem768x25519 KEM; a single 1120-byte
    /// byte string).
    pub kem_ct: Option<Vec<u8>>,
    /// Wrapped CEK + AEAD tag (48 bytes).
    pub wrap: Option<Vec<u8>>,
}

/// A passphrase key-derivation block (`enc.passphrase`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassphraseBlock {
    /// Passphrase-KDF identifier.
    pub alg: String,
    /// KDF salt (16..64 bytes).
    pub salt: Vec<u8>,
    /// KDF parameters (`m`, `t`, `p` for Argon2id), as ordered `(name, value)`.
    pub params: Vec<(String, u64)>,
}

/// A record-level signature entry (`sigs[i]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigEntry {
    /// The detached COSE_Sign1 structure, a single byte string.
    pub cose_sign1: Vec<u8>,
    /// The optional path-2 `cbor<COSE_Key>` sidecar, a single byte string.
    pub cose_key: Option<Vec<u8>>,
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

fn uris_to_cbor(uris: &[String]) -> CborValue {
    CborValue::Array(uris.iter().map(CborValue::text).collect())
}

fn envelope_to_cbor(enc: &EncryptionEnvelope) -> CborValue {
    match enc {
        EncryptionEnvelope::Scheme1(typed) => scheme1_to_cbor(typed),
        // The opaque reading is preserved verbatim, so an accepted record
        // re-encodes to its original bytes (and a signed body re-signs over
        // the exact bytes the producer covered).
        EncryptionEnvelope::Opaque(value) => value.clone(),
    }
}

fn scheme1_to_cbor(enc: &EncScheme1) -> CborValue {
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
    // in agreement.
    let wrap = CborValue::Bytes(slot.wrap.clone().unwrap_or_default());
    if let Some(kem_ct) = &slot.kem_ct {
        return CborValue::Map(vec![
            (CborValue::text("kem_ct"), CborValue::Bytes(kem_ct.clone())),
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
        CborValue::Bytes(entry.cose_sign1.clone()),
    )];
    if let Some(cose_key) = &entry.cose_key {
        pairs.push((
            CborValue::text("cose_key"),
            CborValue::Bytes(cose_key.clone()),
        ));
    }
    CborValue::Map(pairs)
}

// ===========================================================================
// Validator — options and result types
// ===========================================================================

/// The validation reading for dual-severity envelope dispositions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ValidatorRole {
    /// The default public reading: an envelope under an unsupported `scheme` /
    /// `kem` / `aead` degrades to opaque and `ENC_UNSUPPORTED` is informational.
    #[default]
    Public,
    /// The recipient verifier and strict sealed-crypto mode: the same condition
    /// is a hard reject — `ENC_UNSUPPORTED` escalates to `error` and co-fires
    /// with the identifier-specific `UNSUPPORTED_*` code.
    RecipientOrStrict,
}

/// An upper policy ceiling on Argon2id work factors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2ParamsCeiling {
    /// Memory cost ceiling (KiB).
    pub m: u64,
    /// Iteration-count ceiling.
    pub t: u64,
    /// Parallelism ceiling.
    pub p: u64,
}

/// The reference deployment ceiling on Argon2id work factors — a verifier-side
/// denial-of-service backstop (a 64 GiB `m` must not be able to stall a
/// decrypt-on-paste consumer), enforced by default and distinct from the
/// normative floors. Ceilings are deployment policy, not a wire rule: override
/// per deployment, or set `passphrase_params_ceiling: None` to disable.
pub const DEFAULT_PASSPHRASE_PARAMS_CEILING: Argon2ParamsCeiling = Argon2ParamsCeiling {
    m: 2_097_152, // KiB = 2 GiB
    t: 16,
    p: 8,
};

/// Options for [`validate_poe_record`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorOptions {
    /// Names of the critical extensions this validator implements. Default: the
    /// empty set — a default-configured validator therefore fails every
    /// `crit`-bearing record with `EXTENSION_UNSUPPORTED_CRITICAL`, by design.
    pub supported_critical_extensions: BTreeSet<String>,
    /// The validation reading for dual-severity envelope dispositions.
    pub role: ValidatorRole,
    /// Slot-count resource bound (reference bound 1024; deployments MAY tighten).
    pub max_slots: usize,
    /// Decoded-envelope byte resource bound (reference bound 65536), measured by
    /// re-encoding the decoded `enc` subtree canonically.
    pub max_enc_envelope_bytes: usize,
    /// Upper policy ceiling on Argon2id parameters
    /// (`ENC_PASSPHRASE_PARAMS_EXCEED_POLICY`). Defaults to
    /// [`DEFAULT_PASSPHRASE_PARAMS_CEILING`]; `None` disables the ceiling.
    pub passphrase_params_ceiling: Option<Argon2ParamsCeiling>,
}

impl Default for ValidatorOptions {
    fn default() -> Self {
        Self {
            supported_critical_extensions: BTreeSet::new(),
            role: ValidatorRole::Public,
            max_slots: MAX_SLOTS,
            max_enc_envelope_bytes: MAX_DECODED_ENVELOPE_BYTES,
            passphrase_params_ceiling: Some(DEFAULT_PASSPHRASE_PARAMS_CEILING),
        }
    }
}

/// One segment of an issue path: a text map key or an integer array index.
///
/// The segment list is the API form; a dotted string (e.g.
/// `items.0.hashes.sha2-256`) is a display rendering only, so map keys
/// containing `.` need no escaping.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PathSegment {
    /// A text map key.
    Key(String),
    /// An integer array index.
    Index(usize),
}

impl PathSegment {
    fn key(s: impl Into<String>) -> Self {
        PathSegment::Key(s.into())
    }
}

impl std::fmt::Display for PathSegment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathSegment::Key(k) => f.write_str(k),
            PathSegment::Index(i) => write!(f, "{i}"),
        }
    }
}

/// One entry in the validator's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationIssue {
    /// Segments from the record root: text map keys and integer array indices.
    pub path: Vec<PathSegment>,
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
    /// The record passed: zero error-severity issues. `warning` and `info`
    /// issues (which never fail a record) are carried for inspection.
    Ok {
        /// The decoded record.
        record: Box<PoeRecord>,
        /// Warning-severity issues, sorted.
        warnings: Vec<ValidationIssue>,
        /// Info-severity issues, sorted.
        info: Vec<ValidationIssue>,
    },
    /// The record failed: at least one error-severity issue. The list carries
    /// every collected issue of every severity, sorted.
    Fail {
        /// The full sorted issue list (all severities).
        issues: Vec<ValidationIssue>,
    },
}

impl ValidateResult {
    /// Whether the record passed structural validation.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(self, ValidateResult::Ok { .. })
    }

    /// The distinct error-severity codes, sorted by registry order.
    #[must_use]
    pub fn error_codes(&self) -> BTreeSet<ErrorCode> {
        match self {
            ValidateResult::Ok { .. } => BTreeSet::new(),
            ValidateResult::Fail { issues } => issues
                .iter()
                .filter(|i| i.severity == Severity::Error)
                .map(|i| i.code)
                .collect(),
        }
    }

    /// The distinct info-severity codes, sorted by registry order.
    #[must_use]
    pub fn info_codes(&self) -> BTreeSet<ErrorCode> {
        match self {
            ValidateResult::Ok { info, .. } => info.iter().map(|i| i.code).collect(),
            ValidateResult::Fail { issues } => issues
                .iter()
                .filter(|i| i.severity == Severity::Info)
                .map(|i| i.code)
                .collect(),
        }
    }
}

// ===========================================================================
// Registries (closed catalogue of this implementation)
// ===========================================================================

// Content-hash algorithm registry. Value = digest length.
const HASH_ALG_LENGTHS: &[(&str, usize)] = &[("sha2-256", 32), ("blake2b-256", 32)];

// Merkle list-commitment algorithm registry. Value = root length.
const MERKLE_COMMIT_ALG_LENGTHS: &[(&str, usize)] = &[("rfc9162-sha256", 32)];

// Content-format (AEAD) registry. Value = the registered `enc.nonce` length.
const AEAD_NONCE_LENGTHS: &[(&str, usize)] = &[("chacha20-poly1305-stream64k", 24)];

// Passphrase KDF registry.
const PASSPHRASE_KDF_ALGS: &[&str] = &["argon2id"];

// Signature-algorithm registry: COSE `alg` labels. `-8` (EdDSA, pinned to
// Ed25519) is the mandatory baseline; `-19` (Ed25519 fully-specified) is
// verified identically when accepted. Anything else is tagged
// `SIGNATURE_UNSUPPORTED` (info-severity) — signatures are optional, so an
// unrecognised algorithm never fails the record by itself.
const KNOWN_SIG_ALG_IDS: &[i64] = &[-8, -19];

// Closed top-level base-key set; everything else is extension namespace.
const TOP_LEVEL_BASE_KEYS: &[&str] = &["v", "items", "merkle", "supersedes", "sigs", "crit"];

// Every numeric wire field is a CBOR unsigned integer pinned to this range and
// handled as an exact integer (the `u64` CBOR argument carries the full wire
// range, so no precision is ever lost before the range check rejects).
const UINT32_MAX: u64 = 0xffff_ffff;

// Argon2id parameter floors.
const ARGON2_FLOORS: [(&str, u64); 3] = [("m", 65_536), ("t", 3), ("p", 1)];

/// Which ciphertext-bearing field a KEM uses, plus its exact lengths.
///
/// A descriptor declares the slot's ciphertext-bearing field and its exact byte
/// length; `wrap` is 48 bytes for every KEM (32-byte CEK + 16-byte AEAD tag).
/// The validator branches on the descriptor so adding a future KEM is a
/// registry edit, not a new code path.
#[derive(Debug, Clone, Copy)]
struct KemSlotDescriptor {
    /// `"epk"` for the classical KEM, `"kem_ct"` for the hybrid KEM.
    field: &'static str,
    /// Exact length of the ciphertext-bearing field.
    field_length: usize,
    /// `wrap` length — 32-byte CEK + 16-byte AEAD tag.
    wrap_length: usize,
    /// The length-mismatch code for the ciphertext-bearing field.
    field_length_code: ErrorCode,
}

fn kem_slot_descriptor(kem: &str) -> Option<KemSlotDescriptor> {
    match kem {
        "x25519" => Some(KemSlotDescriptor {
            field: "epk",
            field_length: 32,
            wrap_length: 48,
            field_length_code: ErrorCode::KemEpkLengthMismatch,
        }),
        "mlkem768x25519" => Some(KemSlotDescriptor {
            field: "kem_ct",
            field_length: 1120,
            wrap_length: 48,
            field_length_code: ErrorCode::KemCtLengthMismatch,
        }),
        _ => None,
    }
}

const SLOT_KEY_UNIVERSE: &[&str] = &["epk", "kem_ct", "wrap"];

fn registry_lookup(registry: &[(&str, usize)], key: &str) -> Option<usize> {
    registry
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, len)| *len)
}

/// Whether a key is a vendor (`x-…`) or companion (`<ns>-…`) extension key.
///
/// Vendor form: literal `x-` followed by at least one character. Companion
/// form: one or more ASCII-lowercase letters, a hyphen, then at least one
/// character. In both forms a control character (U+0000–U+001F,
/// U+007F–U+009F) anywhere in the key — including a trailing newline — puts
/// the key outside the namespace.
fn is_extension_key(key: &str) -> bool {
    if key
        .chars()
        .any(|c| matches!(c, '\u{0000}'..='\u{001f}' | '\u{007f}'..='\u{009f}'))
    {
        return false;
    }
    if let Some(rest) = key.strip_prefix("x-") {
        return !rest.is_empty();
    }
    let bytes = key.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_lowercase() {
        i += 1;
    }
    i >= 1 && i < bytes.len() && bytes[i] == b'-' && i + 1 < bytes.len()
}

/// Whether an AEAD identifier names a forbidden unauthenticated cipher.
///
/// Reproduces the reference pattern
/// `(?:^|[-_])(?:cbc|ctr|ecb|cfb|ofb)(?:[-_]|$)|^(?:rc4|des|3des)(?:[-_]|$)`
/// (ASCII case-insensitive): a delimited block-cipher mode token in any
/// key-size spelling (`aes-cbc`, `aes-256-cbc`, `des-ede3-cbc`, …), or a
/// leading legacy stream/block cipher. The token delimiters keep authenticated
/// AEADs (`aes-256-gcm`, `chacha20-poly1305-stream64k`) from matching.
fn is_unauthenticated_cipher(aead: &str) -> bool {
    let lower = aead.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let is_delim = |b: u8| b == b'-' || b == b'_';

    // Arm 1: a delimited mode token anywhere.
    for mode in ["cbc", "ctr", "ecb", "cfb", "ofb"] {
        let m = mode.as_bytes();
        let mut start = 0;
        while let Some(rel) = find_subslice(&bytes[start..], m) {
            let idx = start + rel;
            let before_ok = idx == 0 || is_delim(bytes[idx - 1]);
            let after = idx + m.len();
            let after_ok = after == bytes.len() || is_delim(bytes[after]);
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
            if after == bytes.len() || is_delim(bytes[after]) {
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

// ===========================================================================
// Validator — public entry point
// ===========================================================================

/// Structural validator over canonical-CBOR record-body bytes.
///
/// A pure function: no I/O, no cryptographic signature verification, no
/// decryption, deterministic output for any given `(bytes, options)` pair.
/// Returns the same verdict, the same code set, and the same sorted issue list
/// as the TypeScript and Python SDKs. The record passes iff it emits zero
/// error-severity issues; warning and info issues never fail it.
///
/// Pipeline:
///
/// 1. **Canonical CBOR decode** — every decode failure (malformed bytes,
///    indefinite-length, unsorted/duplicate map keys, non-minimal integers,
///    invalid UTF-8) surfaces as the single `MALFORMED_CBOR` code.
/// 2. **Non-text-key pre-guard** — a map carrying a non-text key at a typed
///    grammar position is `SCHEMA_TYPE_MISMATCH` at the containing map,
///    foreclosing the parse of that subtree.
/// 3. **Schema parse** — closed shapes and per-field CBOR types; a failed
///    parse forecloses the domain pass.
/// 4. **Domain checks** — cross-field rules, registry membership, URI shape,
///    the encryption-envelope union (typed scheme-1 vs the degrade-to-opaque
///    reading), `sigs[i]` COSE structural decode, `crit[]` shape, exact-integer
///    ranges.
/// 5. **Result emission** — issues sorted path segment-wise (integer segments
///    before text, text by UTF-8 bytes, prefix first, same-path tie-break by
///    registry order); valid iff no error-severity issue.
///
/// This implementation never panics: every failure mode maps to an issue.
#[must_use]
pub fn validate_poe_record(bytes: &[u8], options: &ValidatorOptions) -> ValidateResult {
    // Step 1 — canonical CBOR decode.
    let decoded = match decode_canonical_cbor(bytes) {
        Ok(value) => value,
        Err(cause) => {
            return ValidateResult::Fail {
                issues: vec![issue(
                    ErrorCode::MalformedCbor,
                    Vec::new(),
                    format!("cbor decode failed: {cause}"),
                )],
            };
        }
    };

    // Step 2 pre-guard — non-text map keys at the typed grammar positions.
    let pre_guard = collect_non_text_key_map_issues(&decoded);
    if !pre_guard.is_empty() {
        return ValidateResult::Fail {
            issues: sort_issues(pre_guard),
        };
    }

    // Step 2 — schema parse. A failed parse forecloses the domain pass (there
    // is no well-shaped record to walk); its issues are emitted sorted.
    let record_map = match &decoded {
        CborValue::Map(pairs) => pairs,
        _ => {
            return ValidateResult::Fail {
                issues: vec![issue(
                    ErrorCode::SchemaTypeMismatch,
                    Vec::new(),
                    "top-level value must be a CBOR map".to_string(),
                )],
            };
        }
    };
    let schema = schema_issues(record_map);
    if !schema.is_empty() {
        return ValidateResult::Fail {
            issues: sort_issues(schema),
        };
    }

    // Step 3 — domain checks. Issues of every severity are collected together;
    // no error-severity issue stops the walk.
    let mut issues: Vec<ValidationIssue> = Vec::new();

    check_content_commitment_presence(record_map, &mut issues);
    check_crit(record_map, options, &mut issues);

    // Unknown top-level fields: keys outside the base set that match neither
    // extension-key namespace (typos, control-character keys).
    for key in text_keys(record_map) {
        if TOP_LEVEL_BASE_KEYS.contains(&key) || is_extension_key(key) {
            continue;
        }
        issues.push(issue(
            ErrorCode::SchemaUnknownField,
            vec![PathSegment::key(key)],
            format!("unknown top-level field: {key}"),
        ));
    }

    if let Some(CborValue::Array(items)) = map_get(record_map, "items") {
        for (i, item) in items.iter().enumerate() {
            check_item(item, i, options, &mut issues);
        }
    }

    if let Some(CborValue::Array(merkle)) = map_get(record_map, "merkle") {
        for (i, commit) in merkle.iter().enumerate() {
            check_merkle_commit(commit, i, &mut issues);
        }
    }

    if let Some(CborValue::Array(sigs)) = map_get(record_map, "sigs") {
        if sigs.is_empty() {
            issues.push(issue(
                ErrorCode::SchemaTypeMismatch,
                vec![PathSegment::key("sigs")],
                "sigs[] must be non-empty when present".to_string(),
            ));
        }
        for (i, entry) in sigs.iter().enumerate() {
            check_sig_entry(entry, i, &mut issues);
        }
    }

    // Step 4 — result emission.
    let sorted = sort_issues(issues);
    if sorted.iter().any(|i| i.severity == Severity::Error) {
        return ValidateResult::Fail { issues: sorted };
    }
    let warnings = sorted
        .iter()
        .filter(|i| i.severity == Severity::Warning)
        .cloned()
        .collect();
    let info = sorted
        .iter()
        .filter(|i| i.severity == Severity::Info)
        .cloned()
        .collect();
    match record_from_cbor(&decoded) {
        Some(record) => ValidateResult::Ok {
            record: Box::new(record),
            warnings,
            info,
        },
        // record_from_cbor only fails on a shape the schema pass already
        // rejects, so this branch is unreachable for an issue-free record;
        // surface it as a type mismatch rather than panicking.
        None => ValidateResult::Fail {
            issues: vec![issue(
                ErrorCode::SchemaTypeMismatch,
                Vec::new(),
                "record decode produced an unexpected shape".to_string(),
            )],
        },
    }
}

fn issue(code: ErrorCode, path: Vec<PathSegment>, message: String) -> ValidationIssue {
    ValidationIssue {
        path,
        code,
        severity: code.severity(),
        message,
    }
}

// ===========================================================================
// CBOR map accessors
// ===========================================================================

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

/// The map's text keys, in decoded (canonical) order.
fn text_keys(pairs: &[(CborValue, CborValue)]) -> impl Iterator<Item = &str> {
    pairs.iter().filter_map(|(k, _)| match k {
        CborValue::Text(t) => Some(t.as_str()),
        _ => None,
    })
}

/// Whether a decoded value is a CBOR map carrying at least one non-text key.
///
/// Every map at a typed grammar position is text-keyed, so such a map is the
/// non-text-key violation the pre-guard reports at the containing map.
fn is_non_text_key_map(value: &CborValue) -> bool {
    matches!(value, CborValue::Map(pairs)
        if pairs.iter().any(|(k, _)| !matches!(k, CborValue::Text(_))))
}

// ===========================================================================
// Step 2 pre-guard — non-text-key maps
// ===========================================================================

// Non-text-key detection over the typed grammar positions reachable from the
// record root: the root map, each `items[i]` / `merkle[i]` / `sigs[i]` entry,
// and the `hashes` / `enc` maps inside an item. Positions inside extension
// values are deliberately NOT walked — extension values admit any CBOR value
// the canonical profile allows, integer-keyed maps included. The interior of a
// supported `enc` envelope is scanned by the envelope dispatch itself (the
// opaque reading likewise admits arbitrary values).
fn collect_non_text_key_map_issues(decoded: &CborValue) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    let flag = |issues: &mut Vec<ValidationIssue>, path: Vec<PathSegment>| {
        issues.push(issue(
            ErrorCode::SchemaTypeMismatch,
            path,
            "CBOR map carries a non-text key where a text-keyed map is required".to_string(),
        ));
    };
    if is_non_text_key_map(decoded) {
        flag(&mut issues, Vec::new());
        return issues;
    }
    let Some(record_map) = as_map(decoded) else {
        return issues;
    };
    for field in ["items", "merkle", "sigs"] {
        let Some(CborValue::Array(entries)) = map_get(record_map, field) else {
            continue;
        };
        for (i, entry) in entries.iter().enumerate() {
            if is_non_text_key_map(entry) {
                flag(
                    &mut issues,
                    vec![PathSegment::key(field), PathSegment::Index(i)],
                );
                continue;
            }
            if field != "items" {
                continue;
            }
            let Some(item_map) = as_map(entry) else {
                continue;
            };
            for sub in ["hashes", "enc"] {
                if map_get(item_map, sub).is_some_and(is_non_text_key_map) {
                    flag(
                        &mut issues,
                        vec![
                            PathSegment::key(field),
                            PathSegment::Index(i),
                            PathSegment::key(sub),
                        ],
                    );
                }
            }
        }
    }
    issues
}

// ===========================================================================
// Step 2 — schema parse
// ===========================================================================

// The closed-shape gate over the decoded record map. Mirrors the reference
// schema layer exactly: per-field CBOR types, the fixed byte lengths a field
// can assert in isolation (32-byte `supersedes`), the `v == 1` literal, and
// closed-map strictness for `items[i]` / `merkle[i]` / `sigs[i]`. Every issue
// is collected (the walk never stops at the first), and ANY issue forecloses
// the domain pass. Cross-field rules, registry membership, URI shape,
// non-empty-array rules, and integer ranges are domain checks so each emits
// its precise canonical code.
fn schema_issues(record_map: &[(CborValue, CborValue)]) -> Vec<ValidationIssue> {
    let mut out: Vec<ValidationIssue> = Vec::new();

    // `v == 1` literal.
    match map_get(record_map, "v") {
        None => out.push(issue(
            ErrorCode::SchemaMissingRequired,
            vec![PathSegment::key("v")],
            "missing required field 'v'".to_string(),
        )),
        Some(CborValue::Unsigned(1)) => {}
        Some(_) => out.push(issue(
            ErrorCode::SchemaInvalidLiteral,
            vec![PathSegment::key("v")],
            "v must be the literal 1".to_string(),
        )),
    }

    if let Some(items_raw) = map_get(record_map, "items") {
        match items_raw {
            CborValue::Array(items) => {
                for (i, entry) in items.iter().enumerate() {
                    schema_item_issues(entry, i, &mut out);
                }
            }
            _ => out.push(issue(
                ErrorCode::SchemaTypeMismatch,
                vec![PathSegment::key("items")],
                "items must be a CBOR array".to_string(),
            )),
        }
    }

    if let Some(merkle_raw) = map_get(record_map, "merkle") {
        match merkle_raw {
            CborValue::Array(commits) => {
                for (i, entry) in commits.iter().enumerate() {
                    schema_merkle_issues(entry, i, &mut out);
                }
            }
            _ => out.push(issue(
                ErrorCode::SchemaTypeMismatch,
                vec![PathSegment::key("merkle")],
                "merkle must be a CBOR array".to_string(),
            )),
        }
    }

    if let Some(supersedes) = map_get(record_map, "supersedes") {
        match supersedes {
            CborValue::Bytes(b) if b.len() == 32 => {}
            CborValue::Bytes(b) => out.push(issue(
                ErrorCode::SupersedesTxInvalidLength,
                vec![PathSegment::key("supersedes")],
                format!("supersedes length {} != 32", b.len()),
            )),
            _ => out.push(issue(
                ErrorCode::SchemaTypeMismatch,
                vec![PathSegment::key("supersedes")],
                "supersedes must be a CBOR byte string".to_string(),
            )),
        }
    }

    if let Some(sigs_raw) = map_get(record_map, "sigs") {
        match sigs_raw {
            CborValue::Array(entries) => {
                for (i, entry) in entries.iter().enumerate() {
                    schema_sig_issues(entry, i, &mut out);
                }
            }
            _ => out.push(issue(
                ErrorCode::SchemaTypeMismatch,
                vec![PathSegment::key("sigs")],
                "sigs must be a CBOR array".to_string(),
            )),
        }
    }

    if let Some(crit_raw) = map_get(record_map, "crit") {
        match crit_raw {
            CborValue::Array(entries) => {
                for (i, entry) in entries.iter().enumerate() {
                    if !matches!(entry, CborValue::Text(_)) {
                        out.push(issue(
                            ErrorCode::SchemaTypeMismatch,
                            vec![PathSegment::key("crit"), PathSegment::Index(i)],
                            "crit entry must be a text string".to_string(),
                        ));
                    }
                }
            }
            _ => out.push(issue(
                ErrorCode::SchemaTypeMismatch,
                vec![PathSegment::key("crit")],
                "crit must be a CBOR array of text strings".to_string(),
            )),
        }
    }

    out
}

const ITEM_KEYS: &[&str] = &["hashes", "uris", "enc"];

fn schema_item_issues(entry: &CborValue, i: usize, out: &mut Vec<ValidationIssue>) {
    let base = vec![PathSegment::key("items"), PathSegment::Index(i)];
    // Non-text-key maps were foreclosed by the pre-guard, so a Map here is
    // text-keyed.
    let Some(item_map) = as_map(entry) else {
        out.push(issue(
            ErrorCode::SchemaTypeMismatch,
            base,
            "items[] entry must be a CBOR map".to_string(),
        ));
        return;
    };

    match map_get(item_map, "hashes") {
        None => out.push(issue(
            ErrorCode::SchemaMissingRequired,
            with(&base, PathSegment::key("hashes")),
            "item is missing required 'hashes'".to_string(),
        )),
        Some(CborValue::Map(pairs)) => {
            for (alg, digest) in pairs {
                let CborValue::Text(alg) = alg else {
                    continue; // unreachable: hashes maps are text-keyed past the pre-guard
                };
                if !matches!(digest, CborValue::Bytes(_)) {
                    out.push(issue(
                        ErrorCode::SchemaTypeMismatch,
                        with(
                            &with(&base, PathSegment::key("hashes")),
                            PathSegment::key(alg.clone()),
                        ),
                        format!("hashes['{alg}'] digest must be a CBOR byte string"),
                    ));
                }
            }
        }
        Some(_) => out.push(issue(
            ErrorCode::SchemaTypeMismatch,
            with(&base, PathSegment::key("hashes")),
            "hashes must be a CBOR map".to_string(),
        )),
    }

    if let Some(uris_raw) = map_get(item_map, "uris") {
        schema_uris_issues(uris_raw, &with(&base, PathSegment::key("uris")), out);
    }

    // `enc` is held opaque at the item layer: the typed-vs-opaque dispatch in
    // the domain pass narrows it.

    for key in text_keys(item_map) {
        if !ITEM_KEYS.contains(&key) {
            out.push(issue(
                ErrorCode::SchemaUnknownField,
                with(&base, PathSegment::key(key)),
                format!("unrecognized key '{key}' in items[] entry"),
            ));
        }
    }
}

fn schema_uris_issues(raw: &CborValue, base: &[PathSegment], out: &mut Vec<ValidationIssue>) {
    match raw {
        CborValue::Array(uris) => {
            for (j, uri) in uris.iter().enumerate() {
                if !matches!(uri, CborValue::Text(_)) {
                    out.push(issue(
                        ErrorCode::SchemaTypeMismatch,
                        with(base, PathSegment::Index(j)),
                        "uris[] entry must be a single text string".to_string(),
                    ));
                }
            }
        }
        _ => out.push(issue(
            ErrorCode::SchemaTypeMismatch,
            base.to_vec(),
            "uris must be a CBOR array of text strings".to_string(),
        )),
    }
}

const MERKLE_KEYS: &[&str] = &["alg", "root", "leaf_count", "uris"];

fn schema_merkle_issues(entry: &CborValue, i: usize, out: &mut Vec<ValidationIssue>) {
    let base = vec![PathSegment::key("merkle"), PathSegment::Index(i)];
    let Some(commit_map) = as_map(entry) else {
        out.push(issue(
            ErrorCode::SchemaTypeMismatch,
            base,
            "merkle[] entry must be a CBOR map".to_string(),
        ));
        return;
    };

    match map_get(commit_map, "alg") {
        None => out.push(issue(
            ErrorCode::SchemaMissingRequired,
            with(&base, PathSegment::key("alg")),
            "merkle entry is missing required 'alg'".to_string(),
        )),
        Some(CborValue::Text(_)) => {}
        Some(_) => out.push(issue(
            ErrorCode::SchemaTypeMismatch,
            with(&base, PathSegment::key("alg")),
            "merkle entry 'alg' must be a text string".to_string(),
        )),
    }

    match map_get(commit_map, "root") {
        None => out.push(issue(
            ErrorCode::SchemaMissingRequired,
            with(&base, PathSegment::key("root")),
            "merkle entry is missing required 'root'".to_string(),
        )),
        Some(CborValue::Bytes(_)) => {}
        Some(_) => out.push(issue(
            ErrorCode::SchemaTypeMismatch,
            with(&base, PathSegment::key("root")),
            "merkle entry 'root' must be a CBOR byte string".to_string(),
        )),
    }

    // `leaf_count` admits any CBOR integer at the schema layer; the domain pass
    // enforces the unsigned type and the `1 .. 2^32 - 1` range with their
    // precise codes. A missing or non-integer value is the schema-layer type
    // violation.
    match map_get(commit_map, "leaf_count") {
        Some(CborValue::Unsigned(_) | CborValue::Negative(_)) => {}
        _ => out.push(issue(
            ErrorCode::SchemaTypeMismatch,
            with(&base, PathSegment::key("leaf_count")),
            "merkle entry 'leaf_count' must be a CBOR integer".to_string(),
        )),
    }

    if let Some(uris_raw) = map_get(commit_map, "uris") {
        schema_uris_issues(uris_raw, &with(&base, PathSegment::key("uris")), out);
    }

    for key in text_keys(commit_map) {
        if !MERKLE_KEYS.contains(&key) {
            out.push(issue(
                ErrorCode::SchemaUnknownField,
                with(&base, PathSegment::key(key)),
                format!("unrecognized key '{key}' in merkle[] entry"),
            ));
        }
    }
}

const SIG_ENTRY_KEYS: &[&str] = &["cose_sign1", "cose_key"];

fn schema_sig_issues(entry: &CborValue, i: usize, out: &mut Vec<ValidationIssue>) {
    let base = vec![PathSegment::key("sigs"), PathSegment::Index(i)];
    let Some(entry_map) = as_map(entry) else {
        out.push(issue(
            ErrorCode::SigEntryInvalidShape,
            base,
            "sigs[] entry must be the closed map {cose_sign1, ? cose_key}".to_string(),
        ));
        return;
    };

    match map_get(entry_map, "cose_sign1") {
        None => out.push(issue(
            ErrorCode::SigEntryInvalidShape,
            with(&base, PathSegment::key("cose_sign1")),
            "sigs[] entry is missing required 'cose_sign1'".to_string(),
        )),
        Some(CborValue::Bytes(_)) => {}
        Some(_) => out.push(issue(
            ErrorCode::SigEntryInvalidShape,
            with(&base, PathSegment::key("cose_sign1")),
            "sigs[i].cose_sign1 must be a single CBOR byte string".to_string(),
        )),
    }

    if let Some(cose_key) = map_get(entry_map, "cose_key") {
        if !matches!(cose_key, CborValue::Bytes(_)) {
            out.push(issue(
                ErrorCode::SigEntryInvalidShape,
                with(&base, PathSegment::key("cose_key")),
                "sigs[i].cose_key must be a single CBOR byte string".to_string(),
            ));
        }
    }

    for key in text_keys(entry_map) {
        if !SIG_ENTRY_KEYS.contains(&key) {
            out.push(issue(
                ErrorCode::SigEntryInvalidShape,
                with(&base, PathSegment::key(key)),
                format!("sigs[] entry carries unrecognized key '{key}'"),
            ));
        }
    }
}

fn with(base: &[PathSegment], seg: PathSegment) -> Vec<PathSegment> {
    let mut path = base.to_vec();
    path.push(seg);
    path
}

// ===========================================================================
// Step 3 — domain checks
// ===========================================================================

// Content-commitment rule: a record MUST carry at least one of `items[]` or
// `merkle[]` non-empty (SCHEMA_EMPTY_RECORD when both are empty or absent).
// When exactly one of them is present-but-empty beside a non-empty sibling,
// the empty array itself violates its `1*` cardinality.
fn check_content_commitment_presence(
    record_map: &[(CborValue, CborValue)],
    issues: &mut Vec<ValidationIssue>,
) {
    let arr_len = |key: &str| -> Option<usize> {
        match map_get(record_map, key) {
            Some(CborValue::Array(a)) => Some(a.len()),
            _ => None,
        }
    };
    let items_len = arr_len("items");
    let merkle_len = arr_len("merkle");
    if items_len.unwrap_or(0) == 0 && merkle_len.unwrap_or(0) == 0 {
        issues.push(issue(
            ErrorCode::SchemaEmptyRecord,
            Vec::new(),
            "record must carry at least one of items[] or merkle[] non-empty".to_string(),
        ));
        return;
    }
    if items_len == Some(0) {
        issues.push(issue(
            ErrorCode::SchemaTypeMismatch,
            vec![PathSegment::key("items")],
            "items[] must be non-empty when present".to_string(),
        ));
    }
    if merkle_len == Some(0) {
        issues.push(issue(
            ErrorCode::SchemaTypeMismatch,
            vec![PathSegment::key("merkle")],
            "merkle[] must be non-empty when present".to_string(),
        ));
    }
}

// `crit[]` shape rules plus the per-entry critical-extension support check.
fn check_crit(
    record_map: &[(CborValue, CborValue)],
    options: &ValidatorOptions,
    issues: &mut Vec<ValidationIssue>,
) {
    let Some(CborValue::Array(crit)) = map_get(record_map, "crit") else {
        return;
    };
    // `crit` has `1*` cardinality: an empty array is a malformed shape.
    if crit.is_empty() {
        issues.push(issue(
            ErrorCode::SchemaTypeMismatch,
            vec![PathSegment::key("crit")],
            "crit[] must carry at least one entry when present".to_string(),
        ));
        return;
    }
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (i, entry) in crit.iter().enumerate() {
        let Some(name) = as_text(entry) else {
            continue; // unreachable: the schema pass pinned crit entries to text
        };
        let path = vec![PathSegment::key("crit"), PathSegment::Index(i)];
        let reason = if TOP_LEVEL_BASE_KEYS.contains(&name) {
            Some(format!(
                "'{name}' is a base key and MUST NOT appear in crit[]"
            ))
        } else if !is_extension_key(name) {
            Some(format!(
                "'{name}' does not match the extension-key form (^x-… or ^[a-z]+-…, no control characters)"
            ))
        } else if !map_has(record_map, name) {
            Some(format!(
                "'{name}' is named in crit but absent from the record map"
            ))
        } else if seen.contains(name) {
            Some(format!("'{name}' appears more than once in crit[]"))
        } else {
            None
        };
        seen.insert(name);
        if let Some(reason) = reason {
            issues.push(issue(ErrorCode::CritShapeInvalid, path, reason));
            continue;
        }
        // Shape-valid entry: accepted iff this validator implements the named
        // extension. The default supported set is empty, so a default-configured
        // validator fails every `crit`-bearing record — by design.
        if !options.supported_critical_extensions.contains(name) {
            issues.push(issue(
                ErrorCode::ExtensionUnsupportedCritical,
                path,
                format!("crit lists extension '{name}' that this validator does not implement"),
            ));
        }
    }
}

fn check_item(
    item: &CborValue,
    idx: usize,
    options: &ValidatorOptions,
    issues: &mut Vec<ValidationIssue>,
) {
    let Some(item_map) = as_map(item) else {
        return; // unreachable: the schema pass rejected non-map entries
    };
    check_item_hashes(item_map, idx, issues);
    if let Some(uris_raw) = map_get(item_map, "uris") {
        check_uris(
            uris_raw,
            &[
                PathSegment::key("items"),
                PathSegment::Index(idx),
                PathSegment::key("uris"),
            ],
            issues,
        );
    }
    if let Some(enc_raw) = map_get(item_map, "enc") {
        check_item_enc(item_map, enc_raw, idx, options, issues);
    }
}

// Hash-map: non-empty, registry membership, per-algorithm digest length.
fn check_item_hashes(
    item_map: &[(CborValue, CborValue)],
    idx: usize,
    issues: &mut Vec<ValidationIssue>,
) {
    let base = vec![
        PathSegment::key("items"),
        PathSegment::Index(idx),
        PathSegment::key("hashes"),
    ];
    let Some(CborValue::Map(entries)) = map_get(item_map, "hashes") else {
        return; // unreachable: the schema pass pinned hashes to a map
    };
    if entries.is_empty() {
        issues.push(issue(
            ErrorCode::SchemaTypeMismatch,
            base,
            "hashes must be a non-empty CBOR map of <alg-id> -> <digest>".to_string(),
        ));
        return;
    }
    for (alg_key, digest) in entries {
        let (Some(alg), Some(digest)) = (as_text(alg_key), as_bytes(digest)) else {
            continue; // unreachable past the pre-guard + schema pass
        };
        let path = with(&base, PathSegment::key(alg));
        match registry_lookup(HASH_ALG_LENGTHS, alg) {
            None => issues.push(issue(
                ErrorCode::UnsupportedHashAlg,
                path,
                format!("unknown hash alg: {alg}"),
            )),
            Some(expected) => {
                if digest.len() != expected {
                    issues.push(issue(
                        ErrorCode::HashDigestLengthMismatch,
                        path,
                        format!(
                            "hashes['{alg}'] digest length {} != {expected}",
                            digest.len()
                        ),
                    ));
                }
            }
        }
    }
}

// URI shape: each entry is one absolute URI in a single text string.
fn check_uris(raw: &CborValue, base: &[PathSegment], issues: &mut Vec<ValidationIssue>) {
    let CborValue::Array(uris) = raw else {
        return; // unreachable: the schema pass pinned uris to an array
    };
    if uris.is_empty() {
        issues.push(issue(
            ErrorCode::SchemaTypeMismatch,
            base.to_vec(),
            "uris[] must be non-empty when present".to_string(),
        ));
        return;
    }
    for (j, uri) in uris.iter().enumerate() {
        if let Some(uri) = as_text(uri) {
            check_one_uri(uri, with(base, PathSegment::Index(j)), issues);
        }
    }
}

fn check_one_uri(uri: &str, path: Vec<PathSegment>, issues: &mut Vec<ValidationIssue>) {
    // Absolute URI, no fragment, scheme in `{ar://, ipfs://}`.
    if uri.contains('#') {
        issues.push(issue(
            ErrorCode::InvalidUri,
            path,
            "URI contains a fragment identifier ('#'), which is forbidden".to_string(),
        ));
        return;
    }
    let Some(sep_idx) = uri.find("://") else {
        issues.push(issue(
            ErrorCode::InvalidUri,
            path,
            "URI is not absolute (missing scheme://hierarchical-part)".to_string(),
        ));
        return;
    };
    if sep_idx == 0 || !is_uri_scheme(&uri[..sep_idx]) {
        issues.push(issue(
            ErrorCode::InvalidUri,
            path,
            "URI is not absolute (missing scheme://hierarchical-part)".to_string(),
        ));
        return;
    }
    // RFC 3986 §3.1: the scheme is case-insensitive, so case-fold the SCHEME
    // ONLY, then ALWAYS validate the body. The body is matched verbatim — a
    // base64url Arweave txid and a base58btc CID are case-significant.
    let scheme = uri[..sep_idx].to_ascii_lowercase();
    let rest = &uri[sep_idx + "://".len()..];
    match scheme.as_str() {
        "ar" => {
            if !(rest.len() == 43
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
            {
                issues.push(issue(
                    ErrorCode::InvalidUri,
                    path,
                    "ar:// URI does not match `^ar://[A-Za-z0-9_-]{43}$` \
                     (43-char base64url txid, no path/query/fragment)"
                        .to_string(),
                ));
            }
        }
        "ipfs" => {
            // Full offline CID parse (not a prefix heuristic).
            let cid = rest.split('/').next().unwrap_or("");
            if !validate_cid_profile(cid) {
                issues.push(issue(
                    ErrorCode::InvalidUri,
                    path,
                    "ipfs:// URI is not a valid CID under the Label 309 profile".to_string(),
                ));
            }
        }
        _ => issues.push(issue(
            ErrorCode::InvalidUri,
            path,
            "unsupported URI scheme; v1 PoE URI set is {ar://, ipfs://}".to_string(),
        )),
    }
}

/// `^[a-z][a-z0-9+.-]*$`, case-insensitive (RFC 3986 §3.1 scheme grammar).
fn is_uri_scheme(scheme: &str) -> bool {
    let bytes = scheme.as_bytes();
    match bytes.first() {
        Some(b) if b.is_ascii_alphabetic() => {}
        _ => return false,
    }
    bytes[1..]
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'.' || b == b'-')
}

// ===========================================================================
// Encryption envelope — the typed-vs-opaque union
// ===========================================================================
//
// `enc = enc-scheme-1 / enc-opaque`. The disposition is decided by identifier
// support, never by shape success:
//
//   - When `scheme`, `kem`, and `aead` are ALL supported identifiers, the
//     envelope is held to the full scheme-1 shape and key-path rules; an
//     envelope that fails them is rejected with its typed code, never
//     reclassified as opaque.
//   - When any of the three names an identifier this implementation does not
//     support, the envelope becomes OPAQUE: no shape, length, or key-path rule
//     is applied against an unknown identifier; the item is tagged
//     ENC_UNSUPPORTED (info in the public reading; error co-firing with the
//     identifier-specific UNSUPPORTED_* code in the recipient role / strict
//     sealed-crypto mode).
//   - Carve-out: an `aead` naming a forbidden unauthenticated cipher family is
//     rejected UNAUTHENTICATED_CIPHER_FORBIDDEN in every role — a recognised
//     hazard, not an unknown identifier.
//
// The content-hash binding (ENC_REQUIRES_CONTENT_HASH) inspects the item's
// `hashes` map, not the envelope, so it applies even under an opaque envelope.

fn check_item_enc(
    item_map: &[(CborValue, CborValue)],
    raw_enc: &CborValue,
    idx: usize,
    options: &ValidatorOptions,
    issues: &mut Vec<ValidationIssue>,
) {
    let enc_path = vec![
        PathSegment::key("items"),
        PathSegment::Index(idx),
        PathSegment::key("enc"),
    ];

    // Content-hash binding: an `enc`-bearing item MUST commit to at least one
    // REGISTERED content hash — the ciphertext is otherwise bound to no
    // plaintext digest. A presence check, not a non-empty check: `{md5: …}`
    // fails it (and MAY co-fire with UNSUPPORTED_HASH_ALG on the same item).
    let has_content_hash = matches!(map_get(item_map, "hashes"), Some(CborValue::Map(pairs))
        if pairs.iter().any(|(k, _)| matches!(k, CborValue::Text(alg)
            if registry_lookup(HASH_ALG_LENGTHS, alg).is_some())));
    if !has_content_hash {
        issues.push(issue(
            ErrorCode::EncRequiresContentHash,
            enc_path.clone(),
            "item carries `enc` but `hashes` has no registered content-hash entry \
             (sha2-256 or blake2b-256)"
                .to_string(),
        ));
    }

    // The pre-guard has already rejected an `enc` map carrying non-text keys,
    // so a well-typed envelope arrives here as a text-keyed map.
    let Some(enc_map) = as_map(raw_enc) else {
        issues.push(issue(
            ErrorCode::SchemaTypeMismatch,
            enc_path,
            "enc must be a CBOR map".to_string(),
        ));
        return;
    };

    // Decoded-envelope byte resource bound — a generic decode limit that
    // applies in every reading, opaque included. Canonical decode → canonical
    // encode is byte-identical, so re-encoding the decoded envelope measures
    // exactly the wire bytes of the `enc` subtree.
    if let Ok(envelope_bytes) = encode_canonical_cbor(raw_enc) {
        if envelope_bytes.len() > options.max_enc_envelope_bytes {
            issues.push(issue(
                ErrorCode::EncEnvelopeTooLarge,
                enc_path.clone(),
                format!(
                    "decoded envelope is {} bytes; the resource bound is {}",
                    envelope_bytes.len(),
                    options.max_enc_envelope_bytes
                ),
            ));
        }
    }

    // `scheme` is structurally required in BOTH readings, as a CBOR unsigned
    // integer (the opaque grammar admits any uint; the typed grammar pins 1).
    let scheme = match map_get(enc_map, "scheme") {
        None => {
            issues.push(issue(
                ErrorCode::SchemaMissingRequired,
                with(&enc_path, PathSegment::key("scheme")),
                "enc.scheme is required".to_string(),
            ));
            return;
        }
        Some(CborValue::Unsigned(n)) => *n,
        Some(_) => {
            issues.push(issue(
                ErrorCode::SchemaTypeMismatch,
                with(&enc_path, PathSegment::key("scheme")),
                "enc.scheme must be a CBOR unsigned integer".to_string(),
            ));
            return;
        }
    };

    // Forbidden-cipher carve-out: rejected in every role, never opaque.
    let aead = map_get(enc_map, "aead");
    if let Some(CborValue::Text(aead)) = aead {
        if is_unauthenticated_cipher(aead) {
            issues.push(issue(
                ErrorCode::UnauthenticatedCipherForbidden,
                with(&enc_path, PathSegment::key("aead")),
                format!(
                    "'{aead}' is an unauthenticated cipher; \
                     Label 309 mandates an authenticated (AEAD) cipher"
                ),
            ));
            return;
        }
    }

    // Unknown-envelope rule: collect every identifier outside the implemented
    // set. A non-text `kem` / `aead` is not an identifier at all — it is a type
    // violation of whichever reading applies, handled by the typed pass below.
    let kem = map_get(enc_map, "kem");
    let mut unsupported: Vec<(&'static str, ErrorCode, String)> = Vec::new();
    if scheme != 1 {
        unsupported.push((
            "scheme",
            ErrorCode::UnsupportedEnvelopeScheme,
            scheme.to_string(),
        ));
    }
    if let Some(CborValue::Text(kem)) = kem {
        if kem_slot_descriptor(kem).is_none() {
            unsupported.push(("kem", ErrorCode::UnsupportedKemAlg, kem.clone()));
        }
    }
    if let Some(CborValue::Text(aead)) = aead {
        if registry_lookup(AEAD_NONCE_LENGTHS, aead).is_none() {
            unsupported.push(("aead", ErrorCode::UnsupportedAeadAlg, aead.clone()));
        }
    }
    if !unsupported.is_empty() {
        // Degrade to opaque: the envelope is bounded metadata only. No shape,
        // length, nonce, slot, or key-path rule may be applied against an
        // unknown identifier.
        let named = unsupported
            .iter()
            .map(|(field, _, id)| format!("{field}={id}"))
            .collect::<Vec<_>>()
            .join(", ");
        let message = format!(
            "envelope uses identifiers this implementation does not support ({named}); \
             the envelope is opaque and only the content-hash claim is validated"
        );
        match options.role {
            ValidatorRole::RecipientOrStrict => {
                issues.push(ValidationIssue {
                    path: enc_path.clone(),
                    code: ErrorCode::EncUnsupported,
                    severity: Severity::Error,
                    message,
                });
                for (field, code, id) in unsupported {
                    issues.push(issue(
                        code,
                        with(&enc_path, PathSegment::key(field)),
                        format!("enc.{field} '{id}' is not supported"),
                    ));
                }
            }
            ValidatorRole::Public => issues.push(ValidationIssue {
                path: enc_path.clone(),
                code: ErrorCode::EncUnsupported,
                severity: Severity::Info,
                message,
            }),
        }
        return;
    }

    // Fully supported identifiers → the typed scheme-1 pass is mandatory.
    // Non-text-key maps inside the typed envelope (a slot, the passphrase
    // block, its params) are rejected first, at the containing map — the same
    // pre-guard rule the record level applies, scoped here because only the
    // typed reading constrains the envelope interior.
    let internal = enc_internal_non_text_key_issues(enc_map, &enc_path);
    if !internal.is_empty() {
        issues.extend(internal);
        return;
    }
    let parse = enc_scheme1_schema_issues(enc_map, &enc_path);
    if !parse.is_empty() {
        issues.extend(parse);
        return;
    }
    check_scheme1_envelope(enc_map, &enc_path, options, issues);
}

// Non-text-key maps at the typed envelope's interior positions: each slot, the
// passphrase block, and its `params` map.
fn enc_internal_non_text_key_issues(
    enc_map: &[(CborValue, CborValue)],
    enc_path: &[PathSegment],
) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    let flag = |issues: &mut Vec<ValidationIssue>, path: Vec<PathSegment>| {
        issues.push(issue(
            ErrorCode::SchemaTypeMismatch,
            path,
            "CBOR map carries a non-text key where a text-keyed map is required".to_string(),
        ));
    };
    if let Some(CborValue::Array(slots)) = map_get(enc_map, "slots") {
        for (j, slot) in slots.iter().enumerate() {
            if is_non_text_key_map(slot) {
                flag(
                    &mut issues,
                    with(
                        &with(enc_path, PathSegment::key("slots")),
                        PathSegment::Index(j),
                    ),
                );
            }
        }
    }
    if let Some(passphrase) = map_get(enc_map, "passphrase") {
        if is_non_text_key_map(passphrase) {
            flag(&mut issues, with(enc_path, PathSegment::key("passphrase")));
        } else if let Some(pp_map) = as_map(passphrase) {
            if map_get(pp_map, "params").is_some_and(is_non_text_key_map) {
                flag(
                    &mut issues,
                    with(
                        &with(enc_path, PathSegment::key("passphrase")),
                        PathSegment::key("params"),
                    ),
                );
            }
        }
    }
    issues
}

const ENC_KEYS: &[&str] = &[
    "scheme",
    "aead",
    "kem",
    "nonce",
    "slots",
    "slots_mac",
    "passphrase",
];
const PASSPHRASE_KEYS: &[&str] = &["alg", "salt", "params"];

// The closed scheme-1 envelope shape, applied only when `scheme` / `kem` /
// `aead` are all supported identifiers. Every issue is collected; any issue
// forecloses the key-path / length / registry domain rules below.
fn enc_scheme1_schema_issues(
    enc_map: &[(CborValue, CborValue)],
    enc_path: &[PathSegment],
) -> Vec<ValidationIssue> {
    let mut out = Vec::new();

    // `scheme` is the literal 1 — guaranteed by the dispatch.

    match map_get(enc_map, "aead") {
        None => out.push(issue(
            ErrorCode::SchemaMissingRequired,
            with(enc_path, PathSegment::key("aead")),
            "enc.aead is required".to_string(),
        )),
        Some(CborValue::Text(_)) => {}
        Some(_) => out.push(issue(
            ErrorCode::SchemaTypeMismatch,
            with(enc_path, PathSegment::key("aead")),
            "enc.aead must be a text string".to_string(),
        )),
    }

    if let Some(kem) = map_get(enc_map, "kem") {
        if !matches!(kem, CborValue::Text(_)) {
            out.push(issue(
                ErrorCode::SchemaTypeMismatch,
                with(enc_path, PathSegment::key("kem")),
                "enc.kem must be a text string".to_string(),
            ));
        }
    }

    match map_get(enc_map, "nonce") {
        None => out.push(issue(
            ErrorCode::SchemaMissingRequired,
            with(enc_path, PathSegment::key("nonce")),
            "enc.nonce is required".to_string(),
        )),
        Some(CborValue::Bytes(_)) => {}
        Some(_) => out.push(issue(
            ErrorCode::SchemaTypeMismatch,
            with(enc_path, PathSegment::key("nonce")),
            "enc.nonce must be a CBOR byte string".to_string(),
        )),
    }

    if let Some(slots_raw) = map_get(enc_map, "slots") {
        match slots_raw {
            CborValue::Array(slots) => {
                let slots_base = with(enc_path, PathSegment::key("slots"));
                for (j, slot) in slots.iter().enumerate() {
                    let slot_path = with(&slots_base, PathSegment::Index(j));
                    let Some(slot_map) = as_map(slot) else {
                        out.push(issue(
                            ErrorCode::EncSlotInvalidShape,
                            slot_path,
                            "recipient slot must be a CBOR map".to_string(),
                        ));
                        continue;
                    };
                    // The slot shape here is deliberately PERMISSIVE: which
                    // ciphertext-bearing field is required depends on the
                    // envelope-level `kem`, so the KEM-driven domain gate emits
                    // the precise codes. Only per-field CBOR types are pinned.
                    for field in SLOT_KEY_UNIVERSE {
                        if let Some(value) = map_get(slot_map, field) {
                            if !matches!(value, CborValue::Bytes(_)) {
                                out.push(issue(
                                    ErrorCode::EncSlotInvalidShape,
                                    with(&slot_path, PathSegment::key(*field)),
                                    format!("slot.{field} must be a CBOR byte string"),
                                ));
                            }
                        }
                    }
                }
            }
            _ => out.push(issue(
                ErrorCode::SchemaTypeMismatch,
                with(enc_path, PathSegment::key("slots")),
                "enc.slots must be a CBOR array".to_string(),
            )),
        }
    }

    if let Some(slots_mac) = map_get(enc_map, "slots_mac") {
        match slots_mac {
            CborValue::Bytes(mac) => {
                if mac.len() != 32 {
                    out.push(issue(
                        ErrorCode::EncSlotsMacInvalidLength,
                        with(enc_path, PathSegment::key("slots_mac")),
                        format!("slots_mac length {} != 32", mac.len()),
                    ));
                }
            }
            _ => out.push(issue(
                ErrorCode::SchemaTypeMismatch,
                with(enc_path, PathSegment::key("slots_mac")),
                "enc.slots_mac must be a CBOR byte string".to_string(),
            )),
        }
    }

    if let Some(passphrase) = map_get(enc_map, "passphrase") {
        let pp_path = with(enc_path, PathSegment::key("passphrase"));
        match as_map(passphrase) {
            None => out.push(issue(
                ErrorCode::SchemaTypeMismatch,
                pp_path,
                "enc.passphrase must be a CBOR map".to_string(),
            )),
            Some(pp_map) => {
                match map_get(pp_map, "alg") {
                    None => out.push(issue(
                        ErrorCode::SchemaMissingRequired,
                        with(&pp_path, PathSegment::key("alg")),
                        "passphrase.alg is required".to_string(),
                    )),
                    Some(CborValue::Text(_)) => {}
                    Some(_) => out.push(issue(
                        ErrorCode::SchemaTypeMismatch,
                        with(&pp_path, PathSegment::key("alg")),
                        "passphrase.alg must be a text string".to_string(),
                    )),
                }
                match map_get(pp_map, "salt") {
                    // An absent salt maps to the same code as a wrong-typed
                    // one — the reference schema layer expresses the salt as a
                    // byte string carrying its own length refinements, so its
                    // absence surfaces as the type violation of that shape.
                    None => out.push(issue(
                        ErrorCode::SchemaTypeMismatch,
                        with(&pp_path, PathSegment::key("salt")),
                        "passphrase.salt must be a CBOR byte string of 16..64 bytes".to_string(),
                    )),
                    Some(CborValue::Bytes(salt)) => {
                        if salt.len() < 16 {
                            out.push(issue(
                                ErrorCode::EncPassphraseSaltTooShort,
                                with(&pp_path, PathSegment::key("salt")),
                                format!("passphrase.salt length {} < 16", salt.len()),
                            ));
                        } else if salt.len() > 64 {
                            out.push(issue(
                                ErrorCode::EncPassphraseSaltTooLong,
                                with(&pp_path, PathSegment::key("salt")),
                                format!("passphrase.salt length {} > 64", salt.len()),
                            ));
                        }
                    }
                    Some(_) => out.push(issue(
                        ErrorCode::SchemaTypeMismatch,
                        with(&pp_path, PathSegment::key("salt")),
                        "passphrase.salt must be a CBOR byte string".to_string(),
                    )),
                }
                match map_get(pp_map, "params") {
                    None => out.push(issue(
                        ErrorCode::SchemaMissingRequired,
                        with(&pp_path, PathSegment::key("params")),
                        "passphrase.params is required".to_string(),
                    )),
                    Some(CborValue::Map(_)) => {}
                    Some(_) => out.push(issue(
                        ErrorCode::SchemaTypeMismatch,
                        with(&pp_path, PathSegment::key("params")),
                        "passphrase.params must be a CBOR map".to_string(),
                    )),
                }
                for key in text_keys(pp_map) {
                    if !PASSPHRASE_KEYS.contains(&key) {
                        out.push(issue(
                            ErrorCode::SchemaUnknownField,
                            with(&pp_path, PathSegment::key(key)),
                            format!("unrecognized key '{key}' in passphrase block"),
                        ));
                    }
                }
            }
        }
    }

    for key in text_keys(enc_map) {
        if !ENC_KEYS.contains(&key) {
            out.push(issue(
                ErrorCode::SchemaUnknownField,
                with(enc_path, PathSegment::key(key)),
                format!("unrecognized key '{key}' in a supported enc envelope"),
            ));
        }
    }

    out
}

fn check_scheme1_envelope(
    enc_map: &[(CborValue, CborValue)],
    enc_path: &[PathSegment],
    options: &ValidatorOptions,
    issues: &mut Vec<ValidationIssue>,
) {
    // The schema sub-pass pinned the field types, so the accessors below see
    // their expected shapes.
    let aead = map_get(enc_map, "aead").and_then(as_text).unwrap_or("");
    let kem = map_get(enc_map, "kem").and_then(as_text);

    // Nonce length is registered per content format. Checked only under a
    // supported `aead` — which is guaranteed on this path.
    if let (Some(expected), Some(nonce)) = (
        registry_lookup(AEAD_NONCE_LENGTHS, aead),
        map_get(enc_map, "nonce").and_then(as_bytes),
    ) {
        if nonce.len() != expected {
            issues.push(issue(
                ErrorCode::NonceLengthMismatch,
                with(enc_path, PathSegment::key("nonce")),
                format!("nonce length {} != {expected} for {aead}", nonce.len()),
            ));
        }
    }

    // Key-path cross-field rules. Exactly one of `slots` / `passphrase` is
    // present; `passphrase` forbids `kem`, `slots`, and `slots_mac`; `slots`
    // requires both `kem` and `slots_mac`; `slots_mac` binds nothing without
    // `slots`. Each independent rule emits its own code — they co-fire where
    // several apply.
    let has_slots = map_has(enc_map, "slots");
    let has_slots_mac = map_has(enc_map, "slots_mac");
    let has_passphrase = map_has(enc_map, "passphrase");
    let has_kem = kem.is_some();

    if has_passphrase && (has_slots || has_slots_mac || has_kem) {
        issues.push(issue(
            ErrorCode::EncExclusivityViolation,
            enc_path.to_vec(),
            "enc.passphrase is mutually exclusive with kem / slots / slots_mac; \
             exactly one key path is allowed"
                .to_string(),
        ));
    }
    if has_slots && !has_slots_mac {
        issues.push(issue(
            ErrorCode::EncSlotsMacRequired,
            enc_path.to_vec(),
            "enc.slots present but enc.slots_mac absent".to_string(),
        ));
    }
    if has_slots_mac && !has_slots {
        issues.push(issue(
            ErrorCode::EncSlotsRequired,
            enc_path.to_vec(),
            "enc.slots_mac present but enc.slots absent".to_string(),
        ));
    }
    if has_slots && !has_kem {
        issues.push(issue(
            ErrorCode::EncKemRequired,
            enc_path.to_vec(),
            "enc.slots present but enc.kem absent".to_string(),
        ));
    }
    if !has_slots && !has_passphrase {
        issues.push(issue(
            ErrorCode::EncNoKeyPath,
            enc_path.to_vec(),
            "enc requires either slots or passphrase — no on-chain key path otherwise".to_string(),
        ));
    }

    if let Some(CborValue::Array(slots)) = map_get(enc_map, "slots") {
        let slots_path = with(enc_path, PathSegment::key("slots"));
        if slots.is_empty() {
            issues.push(issue(
                ErrorCode::EncSlotsEmpty,
                slots_path,
                "slots[] must carry at least one slot".to_string(),
            ));
        } else if slots.len() > options.max_slots {
            // Slot-count resource bound: reject before walking any slot, so a
            // hostile record cannot drive unbounded per-slot work.
            issues.push(issue(
                ErrorCode::EncSlotsTooMany,
                slots_path,
                format!(
                    "slots length {} exceeds the slot-count bound {}",
                    slots.len(),
                    options.max_slots
                ),
            ));
        } else if let Some(descriptor) = kem.and_then(kem_slot_descriptor) {
            // Per-slot KEK uniqueness: the zero-nonce per-slot wrap is safe
            // only because each slot draws fresh KEM randomness; two slots
            // sharing the same encapsulation material would derive the same
            // KEK. Reject the repeat before any cryptographic layer would.
            let mut seen_kem_material: std::collections::HashSet<&[u8]> =
                std::collections::HashSet::new();
            for (j, slot) in slots.iter().enumerate() {
                let slot_path = with(&slots_path, PathSegment::Index(j));
                let Some(slot_map) = as_map(slot) else {
                    continue; // the schema sub-pass already rejected non-map slots
                };
                check_slot_shape(slot_map, descriptor, kem.unwrap_or(""), &slot_path, issues);
                if let Some(material) = map_get(slot_map, descriptor.field).and_then(as_bytes) {
                    if !seen_kem_material.insert(material) {
                        issues.push(issue(
                            ErrorCode::EncSlotsDuplicateKemMaterial,
                            with(&slot_path, PathSegment::key(descriptor.field)),
                            format!(
                                "slot {j} {} duplicates an earlier slot — \
                                 per-slot KEK uniqueness is violated",
                                descriptor.field
                            ),
                        ));
                    }
                }
            }
        }
    }

    if has_passphrase {
        if let Some(pp_map) = map_get(enc_map, "passphrase").and_then(as_map) {
            check_passphrase_block(
                pp_map,
                &with(enc_path, PathSegment::key("passphrase")),
                options,
                issues,
            );
        }
    }
}

// KEM-driven per-slot shape gate. The descriptor for the declared envelope
// `kem` pins which ciphertext-bearing field MUST be present at what exact
// length, and forbids everything else: the other KEM's field, any stray key
// (a slot is a CLOSED 2-key map), and a missing required field all surface as
// ENC_SLOT_INVALID_SHAPE.
fn check_slot_shape(
    slot_map: &[(CborValue, CborValue)],
    descriptor: KemSlotDescriptor,
    kem: &str,
    slot_path: &[PathSegment],
    issues: &mut Vec<ValidationIssue>,
) {
    let foreign_field = if descriptor.field == "epk" {
        "kem_ct"
    } else {
        "epk"
    };
    if map_has(slot_map, foreign_field) {
        issues.push(issue(
            ErrorCode::EncSlotInvalidShape,
            with(slot_path, PathSegment::key(foreign_field)),
            format!(
                "slot carries '{foreign_field}' but kem='{kem}' expects '{}'",
                descriptor.field
            ),
        ));
    }
    for key in text_keys(slot_map) {
        if !SLOT_KEY_UNIVERSE.contains(&key) {
            issues.push(issue(
                ErrorCode::EncSlotInvalidShape,
                with(slot_path, PathSegment::key(key)),
                format!(
                    "slot carries unexpected key '{key}'; a slot is a 2-key map {{{}, wrap}}",
                    descriptor.field
                ),
            ));
        }
    }

    match map_get(slot_map, descriptor.field).and_then(as_bytes) {
        None => issues.push(issue(
            ErrorCode::EncSlotInvalidShape,
            with(slot_path, PathSegment::key(descriptor.field)),
            format!(
                "slot for kem='{kem}' is missing required '{}'",
                descriptor.field
            ),
        )),
        Some(ct_field) => {
            if ct_field.len() != descriptor.field_length {
                issues.push(issue(
                    descriptor.field_length_code,
                    with(slot_path, PathSegment::key(descriptor.field)),
                    format!(
                        "slot.{} length {} != {} for {kem}",
                        descriptor.field,
                        ct_field.len(),
                        descriptor.field_length
                    ),
                ));
            }
        }
    }

    match map_get(slot_map, "wrap").and_then(as_bytes) {
        None => issues.push(issue(
            ErrorCode::EncSlotInvalidShape,
            with(slot_path, PathSegment::key("wrap")),
            format!("slot for kem='{kem}' is missing required 'wrap'"),
        )),
        Some(wrap) => {
            if wrap.len() != descriptor.wrap_length {
                issues.push(issue(
                    ErrorCode::WrapLengthMismatch,
                    with(slot_path, PathSegment::key("wrap")),
                    format!(
                        "slot.wrap length {} != {}",
                        wrap.len(),
                        descriptor.wrap_length
                    ),
                ));
            }
        }
    }
}

// Passphrase block: KDF registry membership, then the registered algorithm's
// CLOSED parameter map with exact-integer range, floors, and the deployment
// ceiling. Salt bounds are schema-layer refinements and have already fired.
fn check_passphrase_block(
    pp_map: &[(CborValue, CborValue)],
    pp_path: &[PathSegment],
    options: &ValidatorOptions,
    issues: &mut Vec<ValidationIssue>,
) {
    let alg = map_get(pp_map, "alg").and_then(as_text).unwrap_or("");
    if !PASSPHRASE_KDF_ALGS.contains(&alg) {
        issues.push(issue(
            ErrorCode::EncPassphraseAlgUnsupported,
            with(pp_path, PathSegment::key("alg")),
            format!("unknown passphrase kdf alg: {alg}"),
        ));
        return; // no algorithm-specific params rule can apply
    }

    // argon2id: `params` is the CLOSED map of exactly {m, t, p}.
    let params_path = with(pp_path, PathSegment::key("params"));
    let Some(CborValue::Map(params)) = map_get(pp_map, "params") else {
        return; // unreachable: the schema sub-pass pinned params to a map
    };
    for key in text_keys(params) {
        if !matches!(key, "m" | "t" | "p") {
            issues.push(issue(
                ErrorCode::SchemaUnknownField,
                with(&params_path, PathSegment::key(key)),
                format!("unknown argon2id params field: {key}"),
            ));
        }
    }

    let ceiling = options.passphrase_params_ceiling;
    for (name, floor) in ARGON2_FLOORS {
        let path = with(&params_path, PathSegment::key(name));
        let value = match map_get(params, name) {
            None => {
                issues.push(issue(
                    ErrorCode::SchemaMissingRequired,
                    path,
                    format!("argon2id params.{name} is required"),
                ));
                continue;
            }
            Some(CborValue::Unsigned(n)) => *n,
            Some(_) => {
                // Exact-integer discipline: a negative integer is a different
                // CBOR major type and is never a uint.
                issues.push(issue(
                    ErrorCode::SchemaTypeMismatch,
                    path,
                    format!("argon2id params.{name} must be a CBOR unsigned integer"),
                ));
                continue;
            }
        };
        if value > UINT32_MAX {
            issues.push(issue(
                ErrorCode::SchemaTypeMismatch,
                path,
                format!("argon2id params.{name} exceeds the pinned wire range 0 .. 2^32 - 1"),
            ));
            continue;
        }
        if value < floor {
            issues.push(issue(
                ErrorCode::EncPassphraseArgon2ParamsTooLow,
                path,
                format!("argon2id requires {name} >= {floor}"),
            ));
            continue;
        }
        if let Some(ceiling) = ceiling {
            let max = match name {
                "m" => ceiling.m,
                "t" => ceiling.t,
                _ => ceiling.p,
            };
            if value > max {
                issues.push(issue(
                    ErrorCode::EncPassphraseParamsExceedPolicy,
                    path,
                    format!(
                        "argon2id params.{name} = {value} exceeds the deployment ceiling {max}"
                    ),
                ));
            }
        }
    }
}

// ===========================================================================
// Merkle commitments
// ===========================================================================

fn check_merkle_commit(commit: &CborValue, idx: usize, issues: &mut Vec<ValidationIssue>) {
    let base = vec![PathSegment::key("merkle"), PathSegment::Index(idx)];
    let Some(commit_map) = as_map(commit) else {
        return; // unreachable: the schema pass rejected non-map entries
    };

    let alg = map_get(commit_map, "alg").and_then(as_text).unwrap_or("");
    match registry_lookup(MERKLE_COMMIT_ALG_LENGTHS, alg) {
        None => issues.push(issue(
            ErrorCode::UnsupportedMerkleCommitAlg,
            with(&base, PathSegment::key("alg")),
            format!("unknown merkle commitment alg: {alg}"),
        )),
        Some(expected) => {
            if let Some(root) = map_get(commit_map, "root").and_then(as_bytes) {
                if root.len() != expected {
                    issues.push(issue(
                        ErrorCode::HashDigestLengthMismatch,
                        with(&base, PathSegment::key("root")),
                        format!(
                            "merkle entry root length {} != {expected} for {alg}",
                            root.len()
                        ),
                    ));
                }
            }
        }
    }

    // `leaf_count` is REQUIRED and pinned to `1 .. 2^32 − 1`, compared as an
    // exact integer (the CBOR argument is exact, so 2^53 + 1 cannot round to a
    // boundary value before rejection). A negative value is a CBOR type
    // violation (nint where uint is required), distinct from an out-of-range
    // unsigned value.
    match map_get(commit_map, "leaf_count") {
        Some(CborValue::Unsigned(n)) => {
            if !(1..=UINT32_MAX).contains(n) {
                issues.push(issue(
                    ErrorCode::SchemaMerkleLeafCountInvalid,
                    with(&base, PathSegment::key("leaf_count")),
                    format!("leaf_count {n} is outside the pinned range 1 .. 2^32 - 1"),
                ));
            }
        }
        Some(CborValue::Negative(_)) => issues.push(issue(
            ErrorCode::SchemaTypeMismatch,
            with(&base, PathSegment::key("leaf_count")),
            "leaf_count must be a CBOR unsigned integer".to_string(),
        )),
        _ => {} // unreachable: the schema pass pinned leaf_count to an integer
    }

    if let Some(uris_raw) = map_get(commit_map, "uris") {
        check_uris(uris_raw, &with(&base, PathSegment::key("uris")), issues);
    }
}

// ===========================================================================
// Record-level signature entries
// ===========================================================================

fn check_sig_entry(entry: &CborValue, idx: usize, issues: &mut Vec<ValidationIssue>) {
    let base = vec![PathSegment::key("sigs"), PathSegment::Index(idx)];
    let Some(entry_map) = as_map(entry) else {
        return; // unreachable: the schema pass rejected non-map entries
    };

    // Path-2 `cose_key` private-material guard runs FIRST: a leaked private
    // scalar must be named even when the COSE_Sign1 is also malformed.
    let cose_key = map_get(entry_map, "cose_key").and_then(as_bytes);
    if let Some(key_bytes) = cose_key {
        if let Some(key_issue) =
            inspect_cose_key(key_bytes, idx, with(&base, PathSegment::key("cose_key")))
        {
            issues.push(key_issue);
            return;
        }
    }

    let Some(cose_bytes) = map_get(entry_map, "cose_sign1").and_then(as_bytes) else {
        return; // unreachable: the schema pass requires a byte-string cose_sign1
    };
    let cose = match decode_cose_sign1_structural(cose_bytes) {
        Ok(c) => c,
        Err(message) => {
            issues.push(issue(ErrorCode::MalformedSigCoseSign1, base, message));
            return;
        }
    };

    // Detached-only: the COSE_Sign1 payload MUST be CBOR null. An attached
    // payload — even zero-length — is rejected; a producer chaining a CIP-30
    // signData result must null the payload before embedding.
    if cose.payload_present {
        issues.push(issue(
            ErrorCode::MalformedSigCoseSign1,
            base,
            "COSE_Sign1 payload must be null (detached); attached form forbidden".to_string(),
        ));
        return;
    }

    // Signature-algorithm registry check (info severity — signatures are
    // optional, so an unrecognised algorithm never fails the record alone).
    let alg = cose
        .protected_header
        .as_ref()
        .and_then(|h| int_keyed_get(h, 1))
        .and_then(int_value);
    if !alg.is_some_and(|a| KNOWN_SIG_ALG_IDS.contains(&a)) {
        issues.push(issue(
            ErrorCode::SignatureUnsupported,
            base.clone(),
            "COSE_Sign1 protected alg not in {-8, -19}".to_string(),
        ));
    }

    // Path-1 (32-byte protected-header `kid`) and path-2 (`cose_key` sidecar)
    // are mutually exclusive.
    let kid = cose
        .protected_header
        .as_ref()
        .and_then(|h| int_keyed_get(h, 4));
    let kid_32 = matches!(kid, Some(CborValue::Bytes(b)) if b.len() == 32);
    if kid_32 && cose_key.is_some() {
        issues.push(issue(
            ErrorCode::SigEntryKidCoseKeyConflict,
            base,
            "sigs[i] carries both a 32-byte protected `kid` (path 1) and an inline \
             `cose_key` (path 2); paths are mutually exclusive"
                .to_string(),
        ));
    }
}

// COSE_Key inspector (path-2 `sigs[i].cose_key` blob). Two structural checks:
//   1. Private-material guard (FIRST). COSE_Key label `-4` (the private scalar
//      `d` for OKP / EC2 per RFC 9052 §7.1) → SIG_PRIVATE_KEY_LEAKED.
//      Publishing a private key on the permanent ledger is catastrophic and
//      irreversible, so this is a load-bearing producer-side preflight.
//   2. Positive-shape guard: `kty = 1` (OKP), `crv = 6` (Ed25519), and a
//      32-byte `-2` (x). Any failure → MALFORMED_SIG_COSE_SIGN1.
fn inspect_cose_key(key_bytes: &[u8], i: usize, path: Vec<PathSegment>) -> Option<ValidationIssue> {
    let decoded = match decode_canonical_cbor(key_bytes) {
        Ok(v) => v,
        Err(cause) => {
            return Some(issue(
                ErrorCode::MalformedSigCoseSign1,
                path,
                format!("sigs[{i}].cose_key failed to decode as cbor<COSE_Key>: {cause}"),
            ));
        }
    };
    // A COSE_Key map is int-keyed; the label lookups below simply miss on any
    // other decoded shape, failing the positive kty check.
    let get_label = |label: i64| -> Option<&CborValue> {
        as_map(&decoded).and_then(|pairs| int_keyed_get(pairs, label))
    };

    if get_label(-4).is_some() {
        return Some(issue(
            ErrorCode::SigPrivateKeyLeaked,
            path,
            "cose_key carries COSE_Key private-key material (label -4, the OKP/EC2 private \
             scalar d); publishing a private key on the permanent ledger is forbidden"
                .to_string(),
        ));
    }

    if get_label(1) != Some(&CborValue::Unsigned(1)) {
        return Some(issue(
            ErrorCode::MalformedSigCoseSign1,
            path,
            format!("sigs[{i}].cose_key COSE_Key kty (label 1) must be 1 (OKP)"),
        ));
    }
    if get_label(-1) != Some(&CborValue::Unsigned(6)) {
        return Some(issue(
            ErrorCode::MalformedSigCoseSign1,
            path,
            format!("sigs[{i}].cose_key COSE_Key crv (label -1) must be 6 (Ed25519)"),
        ));
    }
    match get_label(-2) {
        Some(CborValue::Bytes(x)) if x.len() == 32 => None,
        _ => Some(issue(
            ErrorCode::MalformedSigCoseSign1,
            path,
            format!(
                "sigs[{i}].cose_key COSE_Key label -2 must be a 32-byte byte string \
                 (Ed25519 public key)"
            ),
        )),
    }
}

/// A minimally decoded COSE_Sign1 structure.
///
/// The structural validator needs only the protected header map (to read `alg`
/// and `kid`) and whether the payload is present (detached form requires null).
struct CoseSign1Structural {
    protected_header: Option<Vec<(CborValue, CborValue)>>,
    payload_present: bool,
}

/// Structurally decode a COSE_Sign1 blob, reproducing the cross-SDK
/// accept/reject rules: a 4-element array, a byte-string protected header
/// (zero-length `0x40` for an empty header — the wrapped-empty-map form is
/// rejected), a map unprotected header, a `bstr / null` payload, and a 64-byte
/// signature.
///
/// Returns the error message on rejection; the caller surfaces it as
/// [`ErrorCode::MalformedSigCoseSign1`].
fn decode_cose_sign1_structural(data: &[u8]) -> Result<CoseSign1Structural, String> {
    let arr = decode_canonical_cbor(data).map_err(|_| "cose decode failed".to_string())?;
    let elems = match arr {
        CborValue::Array(a) if a.len() == 4 => a,
        _ => return Err("expected 4-element array".to_string()),
    };
    let CborValue::Bytes(protected_bytes) = &elems[0] else {
        return Err("protected_bytes must be bytes".to_string());
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
        let decoded = decode_canonical_cbor(protected_bytes)
            .map_err(|_| "protected header decode failed".to_string())?;
        let map = match decoded {
            CborValue::Map(m) => m,
            _ => return Err("protected header must decode to map".to_string()),
        };
        // An empty protected header MUST encode as the zero-length bstr 0x40,
        // not as a 1-byte bstr wrapping an empty map.
        if map.is_empty() {
            return Err(
                "empty protected header must encode as 0x40 (zero-length bstr)".to_string(),
            );
        }
        Some(map)
    };

    Ok(CoseSign1Structural {
        protected_header,
        payload_present,
    })
}

// --- int-keyed map helpers (COSE_Key / COSE protected header) ---

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
        if int_value(k) == Some(label) {
            Some(v)
        } else {
            None
        }
    })
}

// ===========================================================================
// Issue ordering
// ===========================================================================

// Segment-wise path order: integer segments compare numerically, text segments
// compare by the bytewise order of their UTF-8 encodings, an integer segment
// orders before a text segment where the kinds differ, and a strict prefix
// orders before its extensions. Issues on an identical path tie-break by the
// position of their code in the canonical error-code registry. No
// locale-dependent collation — the ordering is byte-stable across runs and
// across language implementations.
fn compare_issues(a: &ValidationIssue, b: &ValidationIssue) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let n = a.path.len().min(b.path.len());
    for i in 0..n {
        let ord = match (&a.path[i], &b.path[i]) {
            (PathSegment::Index(x), PathSegment::Index(y)) => x.cmp(y),
            (PathSegment::Index(_), PathSegment::Key(_)) => Ordering::Less,
            (PathSegment::Key(_), PathSegment::Index(_)) => Ordering::Greater,
            (PathSegment::Key(x), PathSegment::Key(y)) => x.as_bytes().cmp(y.as_bytes()),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    a.path
        .len()
        .cmp(&b.path.len())
        .then_with(|| a.code.registry_index().cmp(&b.code.registry_index()))
}

fn sort_issues(mut issues: Vec<ValidationIssue>) -> Vec<ValidationIssue> {
    issues.sort_by(compare_issues);
    issues
}

// ===========================================================================
// Decode CborValue → PoeRecord (for the validator's Ok branch)
// ===========================================================================

/// Reconstruct a [`PoeRecord`] from a decoded, structurally-valid CBOR map.
///
/// Called only after the domain pass has emitted zero error issues, so every
/// field has its validated shape; a `None` return is therefore unreachable in
/// practice and is mapped to a type-mismatch issue rather than panicking.
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
        record.items = Some(
            items
                .iter()
                .map(item_from_cbor)
                .collect::<Option<Vec<_>>>()?,
        );
    }
    if let Some(CborValue::Array(merkle)) = map_get(map, "merkle") {
        record.merkle = Some(
            merkle
                .iter()
                .map(merkle_from_cbor)
                .collect::<Option<Vec<_>>>()?,
        );
    }
    if let Some(CborValue::Bytes(s)) = map_get(map, "supersedes") {
        record.supersedes = Some(s.clone());
    }
    if let Some(CborValue::Array(sigs)) = map_get(map, "sigs") {
        record.sigs = Some(sigs.iter().map(sig_from_cbor).collect::<Option<Vec<_>>>()?);
    }
    if let Some(CborValue::Array(crit)) = map_get(map, "crit") {
        record.crit = Some(
            crit.iter()
                .map(|c| as_text(c).map(str::to_string))
                .collect::<Option<Vec<_>>>()?,
        );
    }
    for (key, value) in map {
        if let CborValue::Text(k) = key {
            if !TOP_LEVEL_BASE_KEYS.contains(&k.as_str()) {
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
            .map(|(k, v)| Some((as_text(k)?.to_string(), as_bytes(v)?.to_vec())))
            .collect::<Option<Vec<_>>>()?,
        _ => return None,
    };
    let uris = match map_get(map, "uris") {
        Some(CborValue::Array(u)) => Some(
            u.iter()
                .map(|t| as_text(t).map(str::to_string))
                .collect::<Option<Vec<_>>>()?,
        ),
        _ => None,
    };
    let enc = match map_get(map, "enc") {
        Some(enc) => Some(envelope_from_cbor(enc)?),
        None => None,
    };
    Some(ItemEntry { hashes, uris, enc })
}

// The typed-vs-opaque dispatch, replayed for the Ok-branch record: an envelope
// whose `scheme` / `kem` / `aead` are all supported identifiers was validated
// against the scheme-1 shape and lowers to the typed arm; anything else was
// validated as opaque bounded metadata and is preserved verbatim, so the
// record re-encodes to its original bytes.
fn envelope_from_cbor(value: &CborValue) -> Option<EncryptionEnvelope> {
    let map = as_map(value)?;
    let scheme = match map_get(map, "scheme") {
        Some(CborValue::Unsigned(n)) => *n,
        _ => return Some(EncryptionEnvelope::Opaque(value.clone())),
    };
    let kem_supported = match map_get(map, "kem") {
        Some(CborValue::Text(kem)) => kem_slot_descriptor(kem).is_some(),
        None => true,
        Some(_) => false,
    };
    let aead_supported = matches!(map_get(map, "aead"), Some(CborValue::Text(aead))
        if registry_lookup(AEAD_NONCE_LENGTHS, aead).is_some());
    if scheme != 1 || !kem_supported || !aead_supported {
        return Some(EncryptionEnvelope::Opaque(value.clone()));
    }
    Some(EncryptionEnvelope::Scheme1(EncScheme1 {
        scheme,
        aead: as_text(map_get(map, "aead")?)?.to_string(),
        nonce: as_bytes(map_get(map, "nonce")?)?.to_vec(),
        kem: map_get(map, "kem").and_then(as_text).map(str::to_string),
        slots: match map_get(map, "slots") {
            Some(CborValue::Array(slots)) => Some(
                slots
                    .iter()
                    .map(slot_from_cbor)
                    .collect::<Option<Vec<_>>>()?,
            ),
            _ => None,
        },
        slots_mac: map_get(map, "slots_mac")
            .and_then(as_bytes)
            .map(<[u8]>::to_vec),
        passphrase: match map_get(map, "passphrase") {
            Some(pp) => Some(passphrase_from_cbor(pp)?),
            None => None,
        },
    }))
}

fn slot_from_cbor(value: &CborValue) -> Option<Slot> {
    let map = as_map(value)?;
    Some(Slot {
        epk: map_get(map, "epk").and_then(as_bytes).map(<[u8]>::to_vec),
        kem_ct: map_get(map, "kem_ct")
            .and_then(as_bytes)
            .map(<[u8]>::to_vec),
        wrap: map_get(map, "wrap").and_then(as_bytes).map(<[u8]>::to_vec),
    })
}

fn passphrase_from_cbor(value: &CborValue) -> Option<PassphraseBlock> {
    let map = as_map(value)?;
    let params = match map_get(map, "params")? {
        CborValue::Map(m) => m
            .iter()
            .map(|(k, v)| match v {
                CborValue::Unsigned(n) => Some((as_text(k)?.to_string(), *n)),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?,
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
            Some(CborValue::Array(u)) => Some(
                u.iter()
                    .map(|t| as_text(t).map(str::to_string))
                    .collect::<Option<Vec<_>>>()?,
            ),
            _ => None,
        },
    })
}

fn sig_from_cbor(value: &CborValue) -> Option<SigEntry> {
    let map = as_map(value)?;
    Some(SigEntry {
        cose_sign1: as_bytes(map_get(map, "cose_sign1")?)?.to_vec(),
        cose_key: map_get(map, "cose_key")
            .and_then(as_bytes)
            .map(<[u8]>::to_vec),
    })
}

// ===========================================================================
// Label 309 CID profile
// ===========================================================================

/// Whether a CID conforms to the Label 309 profile for `ipfs://` URIs.
///
/// Accepts CIDv0 (`Qm` prefix, base58btc, sha2-256 multihash) and CIDv1
/// (multibase prefix + version 0x01 + codec + multihash) per the closed
/// profile:
///
/// - Multibase: `b`, `B`, `f`, `F`, `z`
/// - Multicodec: `0x55` (raw), `0x70` (dag-pb), `0x71` (dag-cbor)
/// - Multihash: `0x12` (sha2-256, 32 B), `0xb220` (blake2b-256, 32 B)
#[must_use]
pub fn validate_cid_profile(cid: &str) -> bool {
    if cid.is_empty() {
        return false;
    }
    // CIDv0: a base58btc-encoded sha2-256 multihash. Decode the WHOLE string
    // and verify the multihash prefix (0x12 = sha2-256, 0x20 = 32-byte digest)
    // and total length (34 bytes); a `Qm` prefix alone is not sufficient.
    if cid.starts_with("Qm") {
        return match decode_base58btc(cid) {
            Some(decoded) => decoded.len() == 34 && decoded[0] == 0x12 && decoded[1] == 0x20,
            None => false,
        };
    }
    // CIDv1: multibase + binary CID body.
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
    // CIDv1 layout: <version varint> <multicodec varint> <multihash>
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
        0x12 | 0xb220 => 32u64,
        _ => return false,
    };
    if digest_len != expected {
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
            return None; // overflow guard; the profile uses ≤ 16-bit codes
        }
    }
    None
}

// Multibase decoders for the closed set the CID profile admits.
fn decode_multibase(prefix: char, body: &str) -> Option<Vec<u8>> {
    match prefix {
        'b' => decode_base32(&body.to_ascii_lowercase(), false),
        'B' => decode_base32(&body.to_ascii_uppercase(), true),
        'f' | 'F' => decode_base16(body),
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
    // Multibase strips padding per spec; accept either form for robustness.
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
        let result = validate_poe_record(&bytes, &ValidatorOptions::default());
        assert!(result.is_ok());
    }

    #[test]
    fn body_encoding_strips_sigs_only() {
        let mut with_sigs = minimal_record();
        with_sigs.sigs = Some(vec![SigEntry {
            cose_sign1: vec![0x99u8; 64],
            cose_key: None,
        }]);
        let body = encode_record_body_for_signing(&with_sigs).unwrap();
        let without = encode_poe_record(&minimal_record()).unwrap();
        assert_eq!(body, without);
    }

    #[test]
    fn extension_key_form() {
        assert!(is_extension_key("x-note"));
        assert!(is_extension_key("seal-foo"));
        assert!(is_extension_key("abc-1"));
        assert!(!is_extension_key("x-"));
        assert!(!is_extension_key("X-note"));
        assert!(!is_extension_key("x9-foo"));
        assert!(!is_extension_key("nohyphen"));
        // Control characters anywhere — including a trailing newline — put the
        // key outside the namespace.
        assert!(!is_extension_key("x-note\n"));
        assert!(!is_extension_key("x-a\nb"));
        assert!(!is_extension_key("x-a\u{007f}"));
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
            "3des-cbc",
        ] {
            assert!(is_unauthenticated_cipher(aead), "{aead}");
        }
        for aead in [
            "aes-256-gcm",
            "chacha20-poly1305",
            "chacha20-poly1305-stream64k",
            "aes-256-cbc\n",
        ] {
            assert!(!is_unauthenticated_cipher(aead), "{aead}");
        }
    }

    #[test]
    fn cid_profile_accepts_known_cidv0() {
        assert!(validate_cid_profile(
            "QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH"
        ));
        assert!(!validate_cid_profile("mAYIKsomethingbase64"));
    }

    #[test]
    fn registry_index_is_declaration_order() {
        for (i, code) in ERROR_CODES.iter().enumerate() {
            assert_eq!(code.registry_index(), i);
        }
    }
}
