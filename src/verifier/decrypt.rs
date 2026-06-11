//! Sealed-PoE decryption (the recipient verifier).
//!
//! For each `enc`-bearing item — when the run's decryption keyring is
//! non-empty — the verifier acquires the ciphertext blob (out-of-band bytes,
//! or fetched from `item.uris[]`), dispatches on the item's on-wire key path,
//! and attempts every applicable keyring credential independently:
//!
//! - `enc.slots` — the sealed-PoE trial-decrypt loop: per-slot acceptance
//!   folds the KEM validity bit, the wrap-open, and the slot-set MAC over
//!   `slots_hash` into one constant-time decision, then the recovered CEK
//!   opens the segmented STREAM chunk by chunk.
//! - `enc.passphrase` — Argon2id over the pinned-normalization passphrase,
//!   the leading 32-byte key-commitment header verified in constant time
//!   BEFORE any chunk opens, then the same STREAM open.
//!
//! Failure attribution:
//!
//! - `WRONG_RECIPIENT_KEY` / `TAMPERED_HEADER` bind to ON-CHAIN data (the
//!   slot set and its MAC), so they are terminal for the item no matter which
//!   blob was tried.
//! - `TAMPERED_CIPHERTEXT` is blob-dependent: it holds the blob against the
//!   record only when the blob is ATTRIBUTABLE (out-of-band, or fetched with
//!   a verified content-address binding). The same failure over an
//!   unattributable fetched blob is `URI_PROVIDER_INTEGRITY_MISMATCH`
//!   (warning) and the remaining sources are tried; exhaustion without an
//!   attributable blob ends as `CIPHERTEXT_UNAVAILABLE`.
//! - The post-decryption plaintext-hash recheck needs no attribution
//!   qualifier: ciphertext that opens under the authenticated envelope is
//!   attributed by the AEAD itself, so a recheck mismatch is always
//!   `URI_INTEGRITY_MISMATCH` and the record's verdict is `failed` — no
//!   "decrypted" surface may outrank it.
//!
//! The crypto layer owns the whole passphrase path — the input cap, the
//! pinned normalization profile, Argon2id, the constant-time commitment
//! check, and the chunked content open — so no normalization is re-implemented
//! here.

use std::collections::BTreeMap;

use crate::poe_standard::{
    EncScheme1, EncryptionEnvelope, ErrorCode, ItemEntry, PassphraseBlock, PathSegment, Slot,
};
use crate::sealed_poe::{
    ecies_sealed_poe_unwrap, passphrase_sealed_poe_open, sealed_envelope_from_parsed,
    EciesSealedPoeError, EciesSealedPoeErrorCode, ParsedEnvelope, ParsedSlot, PassphraseOpenArgs,
    PassphraseOpenResult, UnwrapFailureReason, UnwrapKeys, UnwrapResult,
};

use crate::verifier::content::{
    provider_mismatch_path, recompute_item_hashes, walk_blob_sources, BlobWalkEnd,
    ContentFetchPolicy, SourceDecision,
};
use crate::verifier::egress::GatewayFetcher;
use crate::verifier::types::{ContentCheck, Decryption, DecryptionOutcome, VerifierIssue};

pub use crate::sealed_poe::MAX_PASSPHRASE_INPUT_BYTES;

/// The result of one item's decryption attempt set.
pub struct ItemDecryptionResult {
    /// The item's per-claim content-check status.
    pub content_check: ContentCheck,
    /// The decryption outcome surfaced on the report's per-item entry.
    pub decryption: DecryptionOutcome,
}

/// One credential-set attempt over one blob.
enum AttemptOutcome {
    /// The envelope opened end-to-end.
    Opened { plaintext: Vec<u8> },
    /// Bound to on-chain data — retrying with a different blob cannot change
    /// it (`WRONG_RECIPIENT_KEY` or `TAMPERED_HEADER`).
    HeaderFailure { code: ErrorCode },
    /// Blob-dependent: subject to the attribution split.
    BlobFailure,
    /// A caller-input / KDF problem independent of the blob — terminal.
    InputFailure { code: ErrorCode, message: String },
}

/// Map a construction-API rejection to the wire error-code vocabulary. Codes
/// that exist in the wire registry pass through verbatim; every other
/// construction-local rejection maps to `KDF_DERIVATION_FAILED` (the input was
/// rejected before derivation could run).
fn input_failure_from(e: &EciesSealedPoeError) -> AttemptOutcome {
    let code = match e.code {
        EciesSealedPoeErrorCode::EncPassphraseUnnormalizable => {
            ErrorCode::EncPassphraseUnnormalizable
        }
        EciesSealedPoeErrorCode::EncPassphraseEmpty => ErrorCode::EncPassphraseEmpty,
        _ => ErrorCode::KdfDerivationFailed,
    };
    AttemptOutcome::InputFailure {
        code,
        message: e.to_string(),
    }
}

/// Convert the typed `enc` block into the permissive [`ParsedEnvelope`] the
/// crypto layer's [`sealed_envelope_from_parsed`] consumes.
fn to_parsed_envelope(enc: &EncScheme1) -> ParsedEnvelope {
    ParsedEnvelope {
        scheme: i64::try_from(enc.scheme).ok(),
        aead: Some(enc.aead.clone()),
        kem: enc.kem.clone(),
        nonce: Some(enc.nonce.clone()),
        slots: enc.slots.as_ref().map(|slots| {
            slots
                .iter()
                .map(|s: &Slot| ParsedSlot {
                    epk: s.epk.clone(),
                    kem_ct: s.kem_ct.clone(),
                    wrap: s.wrap.clone(),
                })
                .collect()
        }),
        slots_mac: enc.slots_mac.clone(),
    }
}

/// The item's content-hash map in the shape the crypto layer consumes.
fn item_hashes(item: &ItemEntry) -> BTreeMap<String, Vec<u8>> {
    item.hashes.iter().cloned().collect()
}

fn attempt_slots_path(
    enc: &EncScheme1,
    item: &ItemEntry,
    ciphertext: &[u8],
    secret_keys: &[Vec<u8>],
) -> AttemptOutcome {
    let Some(envelope) = sealed_envelope_from_parsed(&to_parsed_envelope(enc)) else {
        // Unreachable on a structurally validated record (the recipient-role
        // validator hard-rejects every envelope it cannot fully validate);
        // defensively classed as a header failure.
        return AttemptOutcome::HeaderFailure {
            code: ErrorCode::TamperedHeader,
        };
    };
    let hashes = item_hashes(item);
    let unwrap = match ecies_sealed_poe_unwrap(
        &envelope,
        ciphertext,
        &hashes,
        UnwrapKeys::Multi(secret_keys),
        None,
    ) {
        Ok(u) => u,
        Err(e) => return input_failure_from(&e),
    };
    match unwrap {
        UnwrapResult::Matched { plaintext } => AttemptOutcome::Opened { plaintext },
        UnwrapResult::NotMatched { reason } => match reason {
            UnwrapFailureReason::WrongRecipientKey => AttemptOutcome::HeaderFailure {
                code: ErrorCode::WrongRecipientKey,
            },
            UnwrapFailureReason::TamperedHeader => AttemptOutcome::HeaderFailure {
                code: ErrorCode::TamperedHeader,
            },
            UnwrapFailureReason::TamperedCiphertext => AttemptOutcome::BlobFailure,
        },
    }
}

/// Read a named Argon2id parameter from the on-wire params list.
fn param(block: &PassphraseBlock, name: &str) -> Option<u64> {
    block
        .params
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| *v)
}

fn attempt_passphrase_path(
    enc: &EncScheme1,
    block: &PassphraseBlock,
    item: &ItemEntry,
    blob: &[u8],
    passphrases: &[String],
) -> AttemptOutcome {
    let (Some(m), Some(t), Some(p)) = (param(block, "m"), param(block, "t"), param(block, "p"))
    else {
        return AttemptOutcome::InputFailure {
            code: ErrorCode::KdfDerivationFailed,
            message: "the on-wire Argon2id parameter set is missing m, t, or p".to_string(),
        };
    };
    let hashes = item_hashes(item);
    let mut first_failure: Option<AttemptOutcome> = None;
    for passphrase in passphrases {
        let outcome = match passphrase_sealed_poe_open(PassphraseOpenArgs {
            blob,
            passphrase,
            aead: &enc.aead,
            alg: &block.alg,
            salt: &block.salt,
            m,
            t,
            p,
            nonce: &enc.nonce,
            hashes: &hashes,
        }) {
            Ok(PassphraseOpenResult::Opened { plaintext }) => AttemptOutcome::Opened { plaintext },
            // Wrong passphrase, tampered salt/params/header fields, a spliced
            // envelope, or a tampered stream — indistinguishable by design.
            Ok(PassphraseOpenResult::Rejected) => AttemptOutcome::BlobFailure,
            Err(e) => input_failure_from(&e),
        };
        if matches!(outcome, AttemptOutcome::Opened { .. }) {
            return outcome;
        }
        first_failure.get_or_insert(outcome);
    }
    // The credential list is non-empty by construction (the caller filtered
    // applicable credentials before dispatching here).
    first_failure.unwrap_or(AttemptOutcome::InputFailure {
        code: ErrorCode::KdfDerivationFailed,
        message: "no passphrase credential was supplied".to_string(),
    })
}

/// Decrypt one `enc`-bearing item with the run's keyring.
#[allow(clippy::too_many_arguments)]
pub fn decrypt_item(
    item: &ItemEntry,
    item_index: usize,
    credentials: &[Decryption],
    out_of_band_ciphertext: Option<&[u8]>,
    fetch_content: bool,
    policy: &ContentFetchPolicy<'_>,
    fetcher: &mut GatewayFetcher<'_>,
    issues: &mut Vec<VerifierIssue>,
) -> ItemDecryptionResult {
    let item_path = vec![
        PathSegment::Key("items".to_string()),
        PathSegment::Index(item_index),
    ];
    let enc_path = || {
        let mut p = item_path.clone();
        p.push(PathSegment::Key("enc".to_string()));
        p
    };

    // Dispatch on the item's on-wire key path. The two paths are mutually
    // exclusive on a validated record (ENC_EXCLUSIVITY_VIOLATION), and the
    // recipient-role validator hard-rejects an envelope it cannot fully
    // validate, so an opaque or path-less envelope here is defensively classed
    // as a header failure.
    let (scheme1, is_slots_path) = match &item.enc {
        Some(EncryptionEnvelope::Scheme1(enc)) if enc.slots.is_some() => (Some(enc), true),
        Some(EncryptionEnvelope::Scheme1(enc)) if enc.passphrase.is_some() => (Some(enc), false),
        _ => (None, false),
    };
    let Some(enc) = scheme1 else {
        issues.push(VerifierIssue::new(
            ErrorCode::TamperedHeader,
            enc_path(),
            "the envelope carries no decryptable key path",
        ));
        return ItemDecryptionResult {
            content_check: ContentCheck::NotChecked,
            decryption: DecryptionOutcome {
                decrypted: false,
                plaintext_hash_ok: None,
                code: Some(ErrorCode::TamperedHeader),
            },
        };
    };

    // Applicable credentials for the item's key path. The keyring is global to
    // the run: every credential of the applicable shape is attempted.
    let mut secret_keys: Vec<Vec<u8>> = Vec::new();
    let mut passphrases: Vec<String> = Vec::new();
    for credential in credentials {
        match credential {
            Decryption::Recipient {
                recipient_secret_key,
            } => secret_keys.push(recipient_secret_key.clone()),
            Decryption::Passphrase { passphrase } => passphrases.push(passphrase.clone()),
        }
    }
    let applicable = if is_slots_path {
        secret_keys.len()
    } else {
        passphrases.len()
    };
    if applicable == 0 {
        issues.push(VerifierIssue::new(
            ErrorCode::WrongDecryptionInputShape,
            enc_path(),
            if is_slots_path {
                "the keyring holds no recipient secret key for this slots-path item"
            } else {
                "the keyring holds no passphrase for this passphrase-path item"
            },
        ));
        return ItemDecryptionResult {
            content_check: ContentCheck::NotChecked,
            decryption: DecryptionOutcome {
                decrypted: false,
                plaintext_hash_ok: None,
                code: Some(ErrorCode::WrongDecryptionInputShape),
            },
        };
    }

    let walk = walk_blob_sources(
        out_of_band_ciphertext,
        item.uris.as_deref().unwrap_or(&[]),
        fetch_content,
        &item_path,
        policy,
        fetcher,
        issues,
        |blob, issues| {
            let outcome = if is_slots_path {
                attempt_slots_path(enc, item, blob.bytes, &secret_keys)
            } else {
                let block: &PassphraseBlock = match &enc.passphrase {
                    Some(b) => b,
                    None => unreachable!("passphrase path implies a passphrase block"),
                };
                attempt_passphrase_path(enc, block, item, blob.bytes, &passphrases)
            };
            match outcome {
                AttemptOutcome::Opened { plaintext } => {
                    let plaintext_hash_ok = recompute_item_hashes(&item.hashes, &plaintext);
                    if plaintext_hash_ok {
                        SourceDecision::Accept(ItemDecryptionResult {
                            content_check: ContentCheck::Checked,
                            decryption: DecryptionOutcome {
                                decrypted: true,
                                plaintext_hash_ok: Some(true),
                                code: None,
                            },
                        })
                    } else {
                        issues.push(VerifierIssue::new(
                            ErrorCode::UriIntegrityMismatch,
                            item_path.clone(),
                            "decryption succeeded but the post-decryption plaintext-hash recheck failed; decrypted bytes are attributed by the AEAD itself, so the record is condemned",
                        ));
                        SourceDecision::Accept(ItemDecryptionResult {
                            content_check: ContentCheck::Mismatched,
                            decryption: DecryptionOutcome {
                                decrypted: true,
                                plaintext_hash_ok: Some(false),
                                code: Some(ErrorCode::UriIntegrityMismatch),
                            },
                        })
                    }
                }
                AttemptOutcome::HeaderFailure { code } => {
                    issues.push(VerifierIssue::new(
                        code,
                        enc_path(),
                        match code {
                            ErrorCode::WrongRecipientKey => {
                                "no slot accepted any supplied recipient key — the key is not a recipient of this sealed PoE"
                            }
                            _ => {
                                "a slot wrap-opened but no candidate content-encryption key reproduces slots_mac — the authenticated envelope header fails its integrity check"
                            }
                        },
                    ));
                    SourceDecision::Accept(ItemDecryptionResult {
                        content_check: ContentCheck::NotChecked,
                        decryption: DecryptionOutcome {
                            decrypted: false,
                            plaintext_hash_ok: None,
                            code: Some(code),
                        },
                    })
                }
                AttemptOutcome::BlobFailure => {
                    if blob.attributable() {
                        issues.push(VerifierIssue::new(
                            ErrorCode::TamperedCiphertext,
                            enc_path(),
                            "the ciphertext blob failed the decryption layer and is attributable (out-of-band, or content-address-bound to its URI); the record is condemned",
                        ));
                        SourceDecision::Accept(ItemDecryptionResult {
                            content_check: ContentCheck::Mismatched,
                            decryption: DecryptionOutcome {
                                decrypted: false,
                                plaintext_hash_ok: None,
                                code: Some(ErrorCode::TamperedCiphertext),
                            },
                        })
                    } else {
                        issues.push(VerifierIssue::new(
                            ErrorCode::UriProviderIntegrityMismatch,
                            provider_mismatch_path(&item_path, blob),
                            format!(
                                "ciphertext bytes fetched from {:?} fail the decryption layer and could not be attributed to the URI's content address; the serving provider is indicted, not the record",
                                blob.uri.unwrap_or("unknown source")
                            ),
                        ));
                        SourceDecision::NextSource
                    }
                }
                AttemptOutcome::InputFailure { code, message } => {
                    issues.push(VerifierIssue::new(code, enc_path(), message));
                    SourceDecision::Accept(ItemDecryptionResult {
                        content_check: ContentCheck::NotChecked,
                        decryption: DecryptionOutcome {
                            decrypted: false,
                            plaintext_hash_ok: None,
                            code: Some(code),
                        },
                    })
                }
            }
        },
    );

    match walk {
        BlobWalkEnd::Done(result) => result,
        BlobWalkEnd::Exhausted { limit_exceeded } => {
            let end_code = if limit_exceeded {
                ErrorCode::ContentFetchLimitExceeded
            } else {
                ErrorCode::CiphertextUnavailable
            };
            issues.push(VerifierIssue::new(
                end_code,
                item_path,
                if limit_exceeded {
                    "a ciphertext fetch for this item was aborted at the max-fetch-bytes ceiling; decryption could not proceed"
                } else {
                    "no out-of-band ciphertext was supplied and no URI yielded an attributable blob; decryption could not proceed"
                },
            ));
            ItemDecryptionResult {
                content_check: ContentCheck::NotChecked,
                decryption: DecryptionOutcome {
                    decrypted: false,
                    plaintext_hash_ok: None,
                    code: Some(end_code),
                },
            }
        }
    }
}

#[cfg(test)]
mod cap_tests {
    //! The pre-KDF passphrase length cap (4096 UTF-8 bytes), enforced by the
    //! crypto layer before normalization / Argon2id, exercised through the
    //! verifier's passphrase attempt: an over-cap passphrase is rejected as
    //! KDF_DERIVATION_FAILED before any KDF work; an at-cap passphrase still
    //! decrypts.

    use super::*;
    use crate::hash::sha256;
    use crate::sealed_poe::{passphrase_sealed_poe_seal, PassphraseSealArgs};

    // Floor-valued Argon2id params: the construction enforces the registry
    // floors at both seal and open, so this is the cheapest set it accepts.
    const M: u64 = 65536;
    const T: u64 = 3;
    const P: u64 = 1;

    fn passphrase_block(salt: &[u8]) -> PassphraseBlock {
        PassphraseBlock {
            alg: "argon2id".to_string(),
            salt: salt.to_vec(),
            params: vec![
                ("m".to_string(), M),
                ("t".to_string(), T),
                ("p".to_string(), P),
            ],
        }
    }

    fn build_blob(passphrase: &str, salt: &[u8], nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let hashes: BTreeMap<String, Vec<u8>> =
            [("sha2-256".to_string(), sha256(plaintext).to_vec())].into();
        passphrase_sealed_poe_seal(PassphraseSealArgs {
            plaintext,
            passphrase,
            salt,
            m: M,
            t: T,
            p: P,
            nonce,
            hashes: &hashes,
        })
        .expect("seal")
    }

    fn item_with(salt: &[u8], nonce: &[u8], plaintext: &[u8]) -> (ItemEntry, EncScheme1) {
        let enc = EncScheme1 {
            scheme: 1,
            aead: "chacha20-poly1305-stream64k".to_string(),
            nonce: nonce.to_vec(),
            kem: None,
            slots: None,
            slots_mac: None,
            passphrase: Some(passphrase_block(salt)),
        };
        let item = ItemEntry {
            hashes: vec![("sha2-256".to_string(), sha256(plaintext).to_vec())],
            uris: None,
            enc: Some(EncryptionEnvelope::Scheme1(enc.clone())),
        };
        (item, enc)
    }

    fn attempt(
        item: &ItemEntry,
        enc: &EncScheme1,
        blob: &[u8],
        passphrase: &str,
    ) -> AttemptOutcome {
        let block = enc.passphrase.as_ref().expect("passphrase block");
        attempt_passphrase_path(enc, block, item, blob, &[passphrase.to_string()])
    }

    #[test]
    fn cap_constant_is_4096_bytes() {
        assert_eq!(MAX_PASSPHRASE_INPUT_BYTES, 4096);
    }

    #[test]
    fn over_byte_cap_is_rejected_kdf_failed() {
        let salt = [0x42u8; 16];
        let nonce = [0x00u8; 24];
        let plaintext = b"cap test";
        // The blob is sealed under an in-cap passphrase; the oversized entry is
        // rejected at the input cap before any KDF work.
        let blob = build_blob("in-cap passphrase", &salt, &nonce, plaintext);
        let oversized = "a".repeat(MAX_PASSPHRASE_INPUT_BYTES + 1); // 4097 ASCII bytes
        let (item, enc) = item_with(&salt, &nonce, plaintext);
        let outcome = attempt(&item, &enc, &blob, &oversized);
        assert!(matches!(
            outcome,
            AttemptOutcome::InputFailure {
                code: ErrorCode::KdfDerivationFailed,
                ..
            }
        ));
    }

    #[test]
    fn exactly_at_cap_is_accepted() {
        let salt = [0x42u8; 16];
        let nonce = [0x00u8; 24];
        let plaintext = b"cap test";
        let at_cap = "a".repeat(MAX_PASSPHRASE_INPUT_BYTES); // 4096 ASCII bytes
        let blob = build_blob(&at_cap, &salt, &nonce, plaintext);
        let (item, enc) = item_with(&salt, &nonce, plaintext);
        let outcome = attempt(&item, &enc, &blob, &at_cap);
        let AttemptOutcome::Opened { plaintext: opened } = outcome else {
            panic!("at-cap passphrase must decrypt");
        };
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn cap_measures_bytes_not_code_points() {
        // U+1F680 (rocket) is 4 UTF-8 bytes per code point. 1025 of them = 4100
        // bytes but only 1025 code points — under any char-count limit, over the
        // byte cap.
        let salt = [0x42u8; 16];
        let nonce = [0x00u8; 24];
        let plaintext = b"cap test";
        let blob = build_blob("in-cap passphrase", &salt, &nonce, plaintext);
        let multibyte_over_cap = "\u{1F680}".repeat(1025);
        assert!(multibyte_over_cap.chars().count() < MAX_PASSPHRASE_INPUT_BYTES);
        assert!(multibyte_over_cap.len() > MAX_PASSPHRASE_INPUT_BYTES);
        let (item, enc) = item_with(&salt, &nonce, plaintext);
        let outcome = attempt(&item, &enc, &blob, &multibyte_over_cap);
        assert!(matches!(
            outcome,
            AttemptOutcome::InputFailure {
                code: ErrorCode::KdfDerivationFailed,
                ..
            }
        ));
    }
}
