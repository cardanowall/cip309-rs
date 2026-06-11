//! The sealed-PoE construction (`enc.scheme: 1`): multi-recipient and
//! passphrase encryption for Proof-of-Existence content.
//!
//! A sealed PoE encrypts content once under a random content-encryption key
//! (CEK) in the `chacha20-poly1305-stream64k` segmented STREAM format, then
//! delivers that CEK either through per-recipient KEM slots (`x25519` or the
//! X-Wing `mlkem768x25519` hybrid) or through an Argon2id-stretched
//! passphrase. The module layers:
//!
//! - [`aead`] — the AEAD primitives: ChaCha20-Poly1305 (RFC 8439) for the
//!   per-slot CEK wrap and the STREAM chunks, plus XChaCha20-Poly1305 as a
//!   general-purpose primitive (not used by the sealed-PoE content layer).
//! - [`kem`] — classical X25519 ECDH (RFC 7748, with the all-zero rejection)
//!   and the X-Wing hybrid KEM (ML-KEM-768 + X25519).
//! - [`stream`] — the segmented STREAM content format (chunk machines and
//!   whole-buffer helpers).
//! - [`transcript`] — the byte-critical shared core: `hashes_hash`, the slots
//!   and passphrase transcripts, the payload-key derivations, and the per-slot
//!   KEK salts.
//! - [`wrap`] / [`unwrap`] — the slots path: producer wrap and the recipient
//!   trial-decrypt with the per-slot MAC fold.
//! - [`passphrase`] / [`normalize`] — the passphrase path: seal/open with the
//!   in-ciphertext key commitment, and the pinned passphrase normalization
//!   profile.
//! - [`envelope`] / [`slots`] / [`errors`] — wire shapes and the typed error
//!   taxonomy.
//!
//! Every output here is reproduced byte-for-byte by the TypeScript
//! (`@cardanowall/sdk-ts`) and Python (`cardanowall-sdk`) SDKs and is pinned
//! against the shared cross-implementation test vectors.

pub mod aead;
pub mod envelope;
pub mod errors;
pub mod kem;
pub mod normalize;
pub mod passphrase;
pub mod slots;
pub mod stream;
pub mod transcript;
pub mod unwrap;
pub mod wrap;

pub use aead::{
    chacha20_poly1305_decrypt, chacha20_poly1305_encrypt, xchacha20_poly1305_decrypt,
    xchacha20_poly1305_encrypt, AeadError,
};
pub use kem::{
    mlkem768x25519_decapsulate, mlkem768x25519_encapsulate, mlkem768x25519_public_key_from_seed,
    x25519_ecdh, x25519_ecdh_unvalidated, x25519_public_key, KemError, MLKEM768X25519_ENC_LENGTH,
    MLKEM768X25519_ESEED_LENGTH, MLKEM768X25519_PUBLIC_KEY_LENGTH,
    MLKEM768X25519_SHARED_SECRET_LENGTH, MLKEM768X25519_SK_SEED_LENGTH,
};

pub use envelope::{sealed_envelope_from_parsed, ParsedEnvelope, ParsedSlot};
pub use errors::{EciesSealedPoeError, EciesSealedPoeErrorCode};
pub use normalize::{normalize_passphrase, MAX_PASSPHRASE_INPUT_BYTES, UNICODE_WHITE_SPACE};
pub use passphrase::{
    passphrase_sealed_poe_open, passphrase_sealed_poe_seal, PassphraseOpenArgs,
    PassphraseOpenResult, PassphraseSealArgs, MAX_PASSPHRASE_SALT_LENGTH,
    MIN_PASSPHRASE_SALT_LENGTH, PASSPHRASE_COMMITMENT_LENGTH, PASSPHRASE_KDF_ARGON2ID,
};
pub use slots::{
    Mlkem768X25519Slot, SealedEnvelope, SealedPoeOutput, SealedSlots, X25519Slot,
    AEAD_CHACHA20_POLY1305_STREAM64K, KEM_MLKEM768X25519, KEM_X25519,
};
pub use stream::{
    stream_open, stream_seal, StreamError, StreamOpener, StreamSealer, CHUNK_SIZE, TAG_SIZE,
};
pub use transcript::{
    compute_passphrase_hash, compute_slots_hash, item_hashes_hash, passphrase_payload_key,
    passphrase_transcript_bytes, slots_payload_key, slots_transcript_bytes, x25519_kek_salt,
    xwing_kek_salt, CARDANO_POE_HASH_PREFIX_ITEM_HASHES,
    CARDANO_POE_HASH_PREFIX_PASSPHRASE_TRANSCRIPT, CARDANO_POE_HASH_PREFIX_SLOTS_TRANSCRIPT,
    CARDANO_POE_HASH_PREFIX_X25519_KEK_SALT, CARDANO_POE_HASH_PREFIX_XWING_KEK_SALT,
    CARDANO_POE_HKDF_INFO_PASSPHRASE_MAC, CARDANO_POE_HKDF_INFO_PAYLOAD,
    CARDANO_POE_HKDF_INFO_PAYLOAD_PASSPHRASE, CARDANO_POE_PW_NORM_PROFILE,
    MAX_DECODED_ENVELOPE_BYTES, MAX_SLOTS,
};
pub use unwrap::{
    ecies_sealed_poe_trial_decrypt, ecies_sealed_poe_unwrap, PrivsAttempted, RecipientKeyBundle,
    SlotsAttempted, TrialDecryptKeys, TrialDecryptResult, UnwrapFailureReason, UnwrapKeys,
    UnwrapProbe, UnwrapResult,
};
pub use wrap::{
    ecies_sealed_poe_wrap_secure, ecies_sealed_poe_wrap_with_rng, uniform_index_ceiling,
    RandomSource, SealedKem, WrapArgs, CARDANO_POE_HKDF_INFO_KEK,
    CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519, CARDANO_POE_HKDF_INFO_SLOTS_MAC,
};
