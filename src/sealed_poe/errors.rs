//! Sealed-PoE wire-shape and input-validation error taxonomy.
//!
//! These are the typed failures the wrap, unwrap, trial-decrypt, and
//! passphrase seal/open paths raise *before* (and around) the cryptographic
//! core: a bad recipient-key length, an unsupported algorithm identifier, a
//! slot field that is the wrong size. They map one-to-one onto the
//! `EciesSealedPoeError` codes the TypeScript and Python SDKs raise, so
//! cross-implementation tests can assert the exact same `code` string. Codes
//! that name a condition the wire-format registry also names reuse the
//! registry string verbatim; conditions with no wire counterpart (RNG
//! failures, raw input length errors) carry construction-only names.
//!
//! A failed *decryption* (wrong recipient key, a tampered MAC, a tampered
//! ciphertext, a wrong passphrase) is NOT an error here — it is a structured
//! non-match returned by the unwrap / open path, never an exception. The codes
//! below are reserved for malformed input and unsupported-algorithm conditions
//! the caller can fix.

use thiserror::Error;

/// A sealed-PoE input-validation or wire-shape failure.
///
/// The `code()` accessor yields the stable SCREAMING_SNAKE_CASE string shared
/// with the reference SDKs; the `Display` form adds a human-readable message.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{code}: {message}")]
pub struct EciesSealedPoeError {
    /// The stable error code, identical across the TypeScript, Python, and Rust
    /// SDKs.
    pub code: EciesSealedPoeErrorCode,
    /// A human-readable description of the specific failure.
    pub message: String,
}

impl EciesSealedPoeError {
    /// Construct an error with the given code and message.
    pub(crate) fn new(code: EciesSealedPoeErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// The stable code string for this error.
    #[must_use]
    pub fn code(&self) -> &'static str {
        self.code.as_str()
    }
}

/// The closed set of sealed-PoE error codes.
///
/// Every variant corresponds to a named code in the TypeScript and Python
/// `EciesSealedPoeErrorCode` union. Decrypt verdicts (`WRONG_RECIPIENT_KEY`,
/// `TAMPERED_HEADER`, `TAMPERED_CIPHERTEXT`) are deliberately absent: they are
/// non-match results, not errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EciesSealedPoeErrorCode {
    /// The recipient/slot count was zero; at least one recipient is required.
    EncSlotsEmpty,
    /// A required `slots` array was absent from the envelope.
    EncSlotsRequired,
    /// A required `slots_mac` field was absent from the envelope.
    EncSlotsMacRequired,
    /// The `slots_mac` was present but not exactly 32 bytes.
    EncSlotsMacInvalidLength,
    /// A recipient public key (wrap) or slot `epk` was the wrong length.
    KemEpkLengthMismatch,
    /// A hybrid slot's `kem_ct` was not exactly the 1120-byte X-Wing
    /// ciphertext.
    KemCtLengthMismatch,
    /// The content-encryption key was not exactly 32 bytes.
    InvalidCekLength,
    /// The envelope nonce was not exactly 24 bytes.
    NonceLengthMismatch,
    /// A supplied ephemeral secret / `eseed` was the wrong length.
    InvalidEphemeralSecretLength,
    /// The count of supplied ephemeral secrets / `eseed`s did not match the
    /// recipient count, or an override was supplied for the wrong KEM.
    EphemeralSecretsCountMismatch,
    /// The envelope `scheme` was not the supported value `1`.
    UnsupportedEnvelopeScheme,
    /// The envelope `aead` was not `chacha20-poly1305-stream64k`.
    UnsupportedAeadAlg,
    /// The envelope `kem` was not `x25519` or `mlkem768x25519`.
    UnsupportedKemAlg,
    /// The parsed envelope shape was structurally invalid.
    InvalidEnvelopeShape,
    /// A recipient secret key was the wrong length, or the unwrap-args form
    /// (single / multi / bundle) was not exactly one non-empty selection.
    InvalidRecipientKey,
    /// A per-slot `wrap` field was not exactly 48 bytes.
    WrapLengthMismatch,
    /// Two slots carry identical per-slot KEM material (a duplicate `epk` for
    /// x25519, or a duplicate `kem_ct` for the hybrid path). The zero-nonce
    /// per-slot wrap is sound only under per-slot KEK uniqueness; repeated KEM
    /// material derives the same KEK and so repeats the (KEK, nonce) pair.
    /// Rejected on both the producer side (before committing to the wire) and
    /// the verifier side (before any decapsulation).
    EncSlotsDuplicateKemMaterial,
    /// The envelope carried more than `MAX_SLOTS` slots. A resource bound a
    /// public parser enforces before any KEM/AEAD primitive, so a malformed
    /// record cannot drive unbounded per-slot work.
    EncSlotsTooMany,
    /// The decoded envelope's aggregate byte size exceeded
    /// `MAX_DECODED_ENVELOPE_BYTES`. A resource backstop enforced before any
    /// KEM/AEAD primitive.
    EncEnvelopeTooLarge,
    /// An `enc`-bearing item's `hashes` map was empty. The construction binds
    /// the ciphertext to the plaintext only through the item's content-hash
    /// claim, so there must be at least one entry to bind.
    EncRequiresContentHash,
    /// The passphrase KDF identifier was not `argon2id` (the sole registered
    /// passphrase KDF).
    EncPassphraseAlgUnsupported,
    /// The passphrase salt was shorter than 16 bytes.
    EncPassphraseSaltTooShort,
    /// The passphrase salt was longer than 64 bytes.
    EncPassphraseSaltTooLong,
    /// The Argon2id parameters were below the registry floors (`m >= 65536`
    /// KiB, `t >= 3`, `p >= 1`). Enforced at both seal and open, before any
    /// KDF work, so a below-floor passphrase envelope is categorically
    /// outside the construction.
    EncPassphraseArgon2ParamsTooLow,
    /// An Argon2id parameter was outside the wire range `0..2^32-1` (a raw
    /// caller-input error with no wire counterpart: the wire encoding cannot
    /// carry such a value as a valid uint).
    InvalidPassphraseParams,
    /// The supplied passphrase normalized to the empty string under the
    /// pinned normalization profile — a whitespace-only or otherwise vacuous
    /// passphrase, which would key the record to a CEK any party can derive.
    EncPassphraseEmpty,
    /// The supplied passphrase contains a code point that Unicode 16.0 leaves
    /// unassigned, refused before any normalization step runs: normalization
    /// of an unassigned code point is not stable across Unicode versions, so
    /// accepting one could silently change the derived key later.
    EncPassphraseUnnormalizable,
    /// The raw passphrase exceeded `MAX_PASSPHRASE_INPUT_BYTES` UTF-8 bytes,
    /// rejected before any normalization or KDF work (a pre-KDF
    /// denial-of-service bound on caller input; no wire counterpart).
    PassphraseInputTooLong,
    /// The passphrase KDF (Argon2id) rejected its inputs at runtime — a
    /// derivation failure distinct from structural parameter checks.
    KdfDerivationFailed,
    /// The operating-system CSPRNG could not be read while drawing the CEK,
    /// content nonce, or per-recipient ephemeral material for a secure wrap.
    /// This is reported, never panicked: a wrap with no entropy must fail
    /// loudly rather than emit a zeroed (globally known) content key.
    ///
    /// This code has no counterpart in the TypeScript / Python SDKs, whose
    /// host runtimes expose an infallible CSPRNG; it is specific to the Rust
    /// secure-by-default wrap, which reads the OS RNG directly.
    RngUnavailable,
}

impl EciesSealedPoeErrorCode {
    /// The stable wire string for this code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EncSlotsEmpty => "ENC_SLOTS_EMPTY",
            Self::EncSlotsRequired => "ENC_SLOTS_REQUIRED",
            Self::EncSlotsMacRequired => "ENC_SLOTS_MAC_REQUIRED",
            Self::EncSlotsMacInvalidLength => "ENC_SLOTS_MAC_INVALID_LENGTH",
            Self::KemEpkLengthMismatch => "KEM_EPK_LENGTH_MISMATCH",
            Self::KemCtLengthMismatch => "KEM_CT_LENGTH_MISMATCH",
            Self::InvalidCekLength => "INVALID_CEK_LENGTH",
            Self::NonceLengthMismatch => "NONCE_LENGTH_MISMATCH",
            Self::InvalidEphemeralSecretLength => "INVALID_EPHEMERAL_SECRET_LENGTH",
            Self::EphemeralSecretsCountMismatch => "EPHEMERAL_SECRETS_COUNT_MISMATCH",
            Self::UnsupportedEnvelopeScheme => "UNSUPPORTED_ENVELOPE_SCHEME",
            Self::UnsupportedAeadAlg => "UNSUPPORTED_AEAD_ALG",
            Self::UnsupportedKemAlg => "UNSUPPORTED_KEM_ALG",
            Self::InvalidEnvelopeShape => "INVALID_ENVELOPE_SHAPE",
            Self::InvalidRecipientKey => "INVALID_RECIPIENT_KEY",
            Self::WrapLengthMismatch => "WRAP_LENGTH_MISMATCH",
            Self::EncSlotsDuplicateKemMaterial => "ENC_SLOTS_DUPLICATE_KEM_MATERIAL",
            Self::EncSlotsTooMany => "ENC_SLOTS_TOO_MANY",
            Self::EncEnvelopeTooLarge => "ENC_ENVELOPE_TOO_LARGE",
            Self::EncRequiresContentHash => "ENC_REQUIRES_CONTENT_HASH",
            Self::EncPassphraseAlgUnsupported => "ENC_PASSPHRASE_ALG_UNSUPPORTED",
            Self::EncPassphraseSaltTooShort => "ENC_PASSPHRASE_SALT_TOO_SHORT",
            Self::EncPassphraseSaltTooLong => "ENC_PASSPHRASE_SALT_TOO_LONG",
            Self::EncPassphraseArgon2ParamsTooLow => "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW",
            Self::InvalidPassphraseParams => "INVALID_PASSPHRASE_PARAMS",
            Self::EncPassphraseEmpty => "ENC_PASSPHRASE_EMPTY",
            Self::EncPassphraseUnnormalizable => "ENC_PASSPHRASE_UNNORMALIZABLE",
            Self::PassphraseInputTooLong => "PASSPHRASE_INPUT_TOO_LONG",
            Self::KdfDerivationFailed => "KDF_DERIVATION_FAILED",
            Self::RngUnavailable => "RNG_UNAVAILABLE",
        }
    }
}

impl std::fmt::Display for EciesSealedPoeErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
