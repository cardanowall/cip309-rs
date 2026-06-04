//! High-level publish helpers and the pluggable signer contract.
//!
//! Three common shapes collapse the uploads + publish flow into a single call:
//!
//! - [`publish_content`] — anchor a single content blob by its digest. No
//!   storage round-trip; the record is built client-side and posted to
//!   `/publish`.
//! - [`publish_prehashed`] — the caller already holds the digest(s).
//! - [`publish_sealed`] — encrypt the content to the recipient public keys
//!   (age-style sealed envelope), upload the ciphertext to Arweave via
//!   `/uploads`, build a Label 309 record with the resulting `ar://` URI, and
//!   submit.
//! - [`publish_merkle`] — commit N leaf hashes under one RFC 9162 root, upload
//!   the canonical leaves-list to Arweave, and bind the root + leaf count.
//!
//! The SDK never holds identity keys. A caller passes a [`Signer`] that owns the
//! Ed25519 private key (in-memory, AWS KMS, GCP HSM, YubiHSM, an air-gapped
//! signer, …); the helper builds the canonical `Sig_structure`, hands the bytes
//! to the signer, validates the returned 64-byte signature, and assembles the
//! COSE_Sign1 into `sigs[0]`. When no signer is supplied the record publishes
//! unsigned.

use crate::client::http::{ClientError, NamespaceConfig};
use crate::client::off_host_sign::{assemble_cose_sign1, prepare_sig_structure};
use crate::client::transport::{MultipartField, RequestBody};
use crate::client::types::{
    MerkleLeaf, PublishContentInput, PublishMerkleInput, PublishMerkleResponse,
    PublishPrehashedInput, PublishResponse, PublishSealedInput, SealedKemChoice, SupportedHashAlg,
    UploadEntry, UploadsResponse,
};
use crate::hash::{blake2b256, sha256};
use crate::merkle::{encode_leaves_list, merkle_root, MERKLE_ALG_ID};
use crate::poe_standard::{
    chunk_uri, encode_poe_record, EncryptionEnvelope, ItemEntry, MerkleCommit, PoeRecord, Slot,
};
use crate::sealed_poe::{ecies_sealed_poe_wrap_secure, SealedKem, SealedSlots, WrapArgs};
use crate::verifier::fetch::HttpMethod;

const ED25519_PUBLIC_KEY_LENGTH: usize = 32;
const ED25519_SIGNATURE_LENGTH: usize = 64;
const X25519_PUBLIC_KEY_LENGTH: usize = 32;
const MLKEM768X25519_PUBLIC_KEY_LENGTH: usize = 1216;
const LEAF_DIGEST_LENGTH: usize = 32;
const DIGEST_BYTE_LENGTH: usize = 32;
const STORAGE_TARGET_ARWEAVE: &str = "arweave";

/// A pluggable Ed25519 signer for the high-level publish helpers.
///
/// The SDK does not hold identity keys; the integrator owns the key material and
/// decides how to expose signing. `signer_pubkey` is the 32-byte raw Ed25519
/// public key; `sign` receives the canonical `Sig_structure` bytes and returns a
/// 64-byte raw Ed25519 signature (the exact input AWS KMS `Sign` accepts for
/// Ed25519 keys).
pub trait Signer {
    /// The 32-byte raw Ed25519 public key.
    fn signer_pubkey(&self) -> Vec<u8>;
    /// Sign the canonical `Sig_structure` bytes, returning a 64-byte signature.
    ///
    /// # Errors
    ///
    /// Returns a boxed error if the underlying signer fails.
    fn sign(&self, sig_structure_bytes: &[u8]) -> Result<Vec<u8>, SignerError>;
}

/// An opaque signer failure surfaced from a [`Signer`] implementation.
#[derive(Debug, thiserror::Error)]
#[error("signer failed: {0}")]
pub struct SignerError(pub String);

/// A client-side publish-helper validation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PublishError {
    /// The signer public key was not a 32-byte Ed25519 key.
    #[error("INVALID_SIGNER_PUBKEY: signer pubkey must be a 32-byte Ed25519 public key")]
    InvalidSignerPubkey,
    /// The signer returned a signature that was not 64 bytes.
    #[error("INVALID_SIGNER_SIGNATURE: signer must return a 64-byte Ed25519 signature")]
    InvalidSignerSignature,
    /// A Merkle leaf was malformed (wrong length or invalid hex).
    #[error("INVALID_LEAVES: a Merkle leaf is malformed")]
    InvalidLeaves,
    /// A supplied digest was the wrong length.
    #[error("INVALID_DIGEST: a digest is the wrong length")]
    InvalidDigest,
    /// A recipient public key was the wrong length for the chosen KEM.
    #[error("INVALID_RECIPIENT: a recipient public key is the wrong length for the chosen KEM")]
    InvalidRecipient,
    /// An unsupported hash algorithm was requested.
    #[error("UNSUPPORTED_HASH_ALG: hash algorithm is not supported")]
    UnsupportedHashAlg,
}

impl PublishError {
    /// The stable discriminator code for this error.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            PublishError::InvalidSignerPubkey => "INVALID_SIGNER_PUBKEY",
            PublishError::InvalidSignerSignature => "INVALID_SIGNER_SIGNATURE",
            PublishError::InvalidLeaves => "INVALID_LEAVES",
            PublishError::InvalidDigest => "INVALID_DIGEST",
            PublishError::InvalidRecipient => "INVALID_RECIPIENT",
            PublishError::UnsupportedHashAlg => "UNSUPPORTED_HASH_ALG",
        }
    }
}

/// The error a high-level publish helper returns.
#[derive(Debug, thiserror::Error)]
pub enum PublishHelperError {
    /// Client-side validation failed before any request was sent.
    #[error(transparent)]
    Validation(#[from] PublishError),
    /// The off-host signer failed.
    #[error(transparent)]
    Signer(#[from] SignerError),
    /// A `/uploads` call came back with at least one failed file.
    #[error(transparent)]
    PartialUpload(#[from] PartialUploadError),
    /// An HTTP/transport error from the gateway.
    #[error(transparent)]
    Http(#[from] ClientError),
    /// The sealed-PoE wrap or another crypto step failed.
    #[error("crypto failure: {0}")]
    Crypto(String),
}

/// Raised when one or more files in a `/uploads` response came back `ok: false`.
///
/// The high-level helpers (`publish_sealed`, `publish_merkle`) escalate any
/// per-file failure into this error so the caller can retry only the failed
/// indices; the low-level `poe.uploads()` returns the mixed response verbatim.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{} of {} upload(s) failed", .failed.len(), .response.uploads.len())]
pub struct PartialUploadError {
    /// The full uploads response (the successful URIs remain valid).
    pub response: UploadsResponse,
    /// The failed entries.
    pub failed: Vec<UploadEntry>,
}

impl PartialUploadError {
    /// Construct the error from a response carrying at least one failure.
    #[must_use]
    pub fn new(response: UploadsResponse) -> Self {
        let failed = response
            .uploads
            .iter()
            .filter(|u| !u.is_ok())
            .cloned()
            .collect();
        Self { response, failed }
    }

    /// The `idx` of every failed entry, in input order.
    #[must_use]
    pub fn failed_indices(&self) -> Vec<u64> {
        self.failed.iter().map(UploadEntry::idx).collect()
    }
}

/// Hash content under the chosen algorithm.
fn hash_content(bytes: &[u8], alg: SupportedHashAlg) -> Vec<u8> {
    match alg {
        SupportedHashAlg::Sha2_256 => sha256(bytes).to_vec(),
        SupportedHashAlg::Blake2b256 => blake2b256(bytes).to_vec(),
    }
}

/// Validate a signer's public key shape before use.
fn assert_signer(signer: &dyn Signer) -> Result<(), PublishError> {
    if signer.signer_pubkey().len() != ED25519_PUBLIC_KEY_LENGTH {
        return Err(PublishError::InvalidSignerPubkey);
    }
    Ok(())
}

/// Encode a record, optionally signing it path-1 first.
fn encode_record(
    record: &PoeRecord,
    signer: Option<&dyn Signer>,
) -> Result<Vec<u8>, PublishHelperError> {
    let Some(signer) = signer else {
        return encode_poe_record(record).map_err(|e| PublishHelperError::Crypto(e.to_string()));
    };
    let pubkey = signer.signer_pubkey();
    let prepared =
        prepare_sig_structure(record, &pubkey).map_err(|_| PublishError::InvalidSignerPubkey)?;
    let signature = signer.sign(&prepared.sig_structure_bytes)?;
    if signature.len() != ED25519_SIGNATURE_LENGTH {
        return Err(PublishError::InvalidSignerSignature.into());
    }
    let assembled = assemble_cose_sign1(record, &pubkey, &signature)
        .map_err(|_| PublishError::InvalidSignerSignature)?;
    let mut signed = record.clone();
    signed.sigs = Some(vec![assembled.sig_entry]);
    encode_poe_record(&signed).map_err(|e| PublishHelperError::Crypto(e.to_string()))
}

/// POST a finalised record to `/publish` and return the response.
fn post_publish(
    config: &NamespaceConfig<'_>,
    record_bytes: &[u8],
    quote_id: &str,
    idempotency_key: Option<&str>,
) -> Result<PublishResponse, PublishHelperError> {
    let body = serde_json::json!({
        "record": hex::encode(record_bytes),
        "quote_id": quote_id,
    });
    let headers = crate::client::http::json_headers(config.api_key.as_deref(), idempotency_key);
    let url = format!("{}/api/v1/poe/publish", config.base_url);
    let response = crate::client::http::send(
        config.transport,
        &url,
        HttpMethod::Post,
        &headers,
        &RequestBody::Json(serde_json::to_string(&body).expect("publish body serialises")),
    )?;
    let dedup_hit = response.status == 200;
    let mut parsed: PublishResponse = crate::client::http::decode(&response.body)?;
    parsed.dedup_hit = dedup_hit;
    Ok(parsed)
}

/// POST blobs to `/uploads`; escalate any per-file failure into
/// [`PartialUploadError`].
fn post_uploads(
    config: &NamespaceConfig<'_>,
    blobs: &[Vec<u8>],
    idempotency_key: Option<&str>,
) -> Result<UploadsResponse, PublishHelperError> {
    let mut fields = vec![MultipartField {
        name: "target".to_string(),
        filename: None,
        content_type: None,
        value: STORAGE_TARGET_ARWEAVE.as_bytes().to_vec(),
    }];
    for (idx, bytes) in blobs.iter().enumerate() {
        fields.push(MultipartField {
            name: format!("file_{idx}"),
            filename: Some(format!("file_{idx}.bin")),
            content_type: Some("application/octet-stream".to_string()),
            value: bytes.clone(),
        });
    }
    let headers =
        crate::client::http::multipart_headers(config.api_key.as_deref(), idempotency_key);
    let url = format!("{}/api/v1/poe/uploads", config.base_url);
    let response = crate::client::http::send(
        config.transport,
        &url,
        HttpMethod::Post,
        &headers,
        &RequestBody::Multipart(fields),
    )?;
    let result: UploadsResponse = crate::client::http::decode(&response.body)?;
    if result.uploads.iter().any(|u| !u.is_ok()) {
        return Err(PartialUploadError::new(result).into());
    }
    Ok(result)
}

/// The first success URI of an uploads response.
fn first_success_uri(response: &UploadsResponse) -> Result<String, PublishHelperError> {
    response
        .uploads
        .iter()
        .find_map(|u| match u {
            UploadEntry::Success { uri, .. } => Some(uri.clone()),
            UploadEntry::Failure { .. } => None,
        })
        .ok_or_else(|| PublishHelperError::Crypto("uploads response carried no success URI".into()))
}

/// Anchor a single content blob by its digest (hash-only).
///
/// # Errors
///
/// Validation, signer, or HTTP failures surface as [`PublishHelperError`].
pub fn publish_content(
    config: &NamespaceConfig<'_>,
    input: &PublishContentInput<'_>,
) -> Result<PublishResponse, PublishHelperError> {
    if let Some(signer) = input.signer {
        assert_signer(signer)?;
    }
    let hash_alg = input.hash_alg.unwrap_or(SupportedHashAlg::Sha2_256);
    let digest = hash_content(&input.content, hash_alg);
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![(hash_alg.as_str().to_string(), digest)],
            uris: None,
            enc: None,
        }]),
        ..PoeRecord::default()
    };
    let record_bytes = encode_record(&record, input.signer)?;
    post_publish(
        config,
        &record_bytes,
        &input.quote_id,
        input.idempotency_key.as_deref(),
    )
}

/// Anchor a precomputed content digest (the caller already holds it).
///
/// # Errors
///
/// Validation, signer, or HTTP failures surface as [`PublishHelperError`].
pub fn publish_prehashed(
    config: &NamespaceConfig<'_>,
    input: &PublishPrehashedInput<'_>,
) -> Result<PublishResponse, PublishHelperError> {
    if let Some(signer) = input.signer {
        assert_signer(signer)?;
    }
    let present: Vec<&(SupportedHashAlg, String)> = input
        .hashes
        .iter()
        .filter(|(_, hex)| !hex.is_empty())
        .collect();
    if present.is_empty() {
        return Err(PublishError::InvalidDigest.into());
    }
    let mut hashes: Vec<(String, Vec<u8>)> = Vec::new();
    for (alg, hex_str) in present {
        let bytes = hex::decode(hex_str).map_err(|_| PublishError::InvalidDigest)?;
        if bytes.len() != DIGEST_BYTE_LENGTH {
            return Err(PublishError::InvalidDigest.into());
        }
        hashes.push((alg.as_str().to_string(), bytes));
    }
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes,
            uris: None,
            enc: None,
        }]),
        ..PoeRecord::default()
    };
    let record_bytes = encode_record(&record, input.signer)?;
    post_publish(
        config,
        &record_bytes,
        &input.quote_id,
        input.idempotency_key.as_deref(),
    )
}

/// Seal content to N recipients, upload the ciphertext, and publish.
///
/// # Errors
///
/// Validation, crypto, signer, partial-upload, or HTTP failures surface as
/// [`PublishHelperError`].
pub fn publish_sealed(
    config: &NamespaceConfig<'_>,
    input: &PublishSealedInput<'_>,
) -> Result<PublishResponse, PublishHelperError> {
    if let Some(signer) = input.signer {
        assert_signer(signer)?;
    }
    if input.recipients.is_empty() {
        return Err(PublishError::InvalidRecipient.into());
    }
    let kem = input.kem.unwrap_or(SealedKemChoice::Mlkem768X25519);
    let expected_len = match kem {
        SealedKemChoice::X25519 => X25519_PUBLIC_KEY_LENGTH,
        SealedKemChoice::Mlkem768X25519 => MLKEM768X25519_PUBLIC_KEY_LENGTH,
    };
    if input.recipients.iter().any(|r| r.len() != expected_len) {
        return Err(PublishError::InvalidRecipient.into());
    }
    let hash_alg = input.hash_alg.unwrap_or(SupportedHashAlg::Sha2_256);
    let plaintext_digest = hash_content(&input.content, hash_alg);

    let sealed_kem = match kem {
        SealedKemChoice::X25519 => SealedKem::X25519,
        SealedKemChoice::Mlkem768X25519 => SealedKem::Mlkem768X25519,
    };
    let sealed = ecies_sealed_poe_wrap_secure(WrapArgs {
        plaintext: &input.content,
        recipient_public_keys: &input.recipients,
        kem: Some(sealed_kem),
        ..WrapArgs::default()
    })
    .map_err(|e| PublishHelperError::Crypto(e.to_string()))?;

    let uploads = post_uploads(
        config,
        &[sealed.ciphertext],
        input.idempotency_key.as_deref(),
    )?;
    let uri = first_success_uri(&uploads)?;

    let envelope = build_envelope(&sealed.envelope);
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![(hash_alg.as_str().to_string(), plaintext_digest)],
            uris: Some(vec![chunk_uri(&uri)]),
            enc: Some(envelope),
        }]),
        ..PoeRecord::default()
    };
    let record_bytes = encode_record(&record, input.signer)?;
    post_publish(
        config,
        &record_bytes,
        &input.quote_id,
        input.idempotency_key.as_deref(),
    )
}

/// Lower an in-memory sealed envelope to the record `enc` shape.
fn build_envelope(env: &crate::sealed_poe::SealedEnvelope) -> EncryptionEnvelope {
    let slots = match &env.slots {
        SealedSlots::X25519(slots) => slots
            .iter()
            .map(|s| Slot {
                epk: Some(s.epk.clone()),
                kem_ct: None,
                wrap: Some(s.wrap.clone()),
            })
            .collect(),
        SealedSlots::Mlkem768X25519(slots) => slots
            .iter()
            .map(|s| Slot {
                epk: None,
                kem_ct: Some(s.kem_ct.clone()),
                wrap: Some(s.wrap.clone()),
            })
            .collect(),
    };
    EncryptionEnvelope {
        scheme: u64::try_from(env.scheme).unwrap_or(1),
        aead: env.aead.clone(),
        nonce: env.nonce.clone(),
        kem: Some(env.kem.clone()),
        slots: Some(slots),
        slots_mac: Some(env.slots_mac.clone()),
        passphrase: None,
    }
}

/// Commit N leaf hashes under one Merkle root, upload the leaves-list, and
/// publish.
///
/// # Errors
///
/// Validation, crypto, signer, partial-upload, or HTTP failures surface as
/// [`PublishHelperError`].
pub fn publish_merkle(
    config: &NamespaceConfig<'_>,
    input: &PublishMerkleInput<'_>,
) -> Result<PublishMerkleResponse, PublishHelperError> {
    if let Some(signer) = input.signer {
        assert_signer(signer)?;
    }
    if let Some(alg) = input.hash_alg {
        if alg != SupportedHashAlg::Sha2_256 {
            return Err(PublishError::UnsupportedHashAlg.into());
        }
    }
    if input.leaves.is_empty() {
        return Err(PublishError::InvalidLeaves.into());
    }

    let mut leaves: Vec<[u8; LEAF_DIGEST_LENGTH]> = Vec::with_capacity(input.leaves.len());
    for leaf in &input.leaves {
        let bytes = match leaf {
            MerkleLeaf::Bytes(b) => b.clone(),
            MerkleLeaf::Hex(h) => hex::decode(h).map_err(|_| PublishError::InvalidLeaves)?,
        };
        let arr: [u8; LEAF_DIGEST_LENGTH] =
            bytes.try_into().map_err(|_| PublishError::InvalidLeaves)?;
        leaves.push(arr);
    }

    let root = merkle_root(&leaves).map_err(|e| PublishHelperError::Crypto(e.to_string()))?;
    let leaves_list = encode_leaves_list(&leaves, &root, None)
        .map_err(|e| PublishHelperError::Crypto(e.to_string()))?;

    let uploads = post_uploads(config, &[leaves_list], input.idempotency_key.as_deref())?;
    let uri = first_success_uri(&uploads)?;

    let merkle_entry = MerkleCommit {
        alg: MERKLE_ALG_ID.to_string(),
        root: root.to_vec(),
        leaf_count: leaves.len() as u64,
        uris: Some(vec![chunk_uri(&uri)]),
    };
    let record = PoeRecord {
        v: 1,
        merkle: Some(vec![merkle_entry]),
        ..PoeRecord::default()
    };
    let record_bytes = encode_record(&record, input.signer)?;
    let published = post_publish(
        config,
        &record_bytes,
        &input.quote_id,
        input.idempotency_key.as_deref(),
    )?;

    Ok(PublishMerkleResponse {
        id: published.id,
        tx_hash: published.tx_hash,
        status: published.status,
        root: hex::encode(root),
        leaf_count: leaves.len() as u64,
        ar_uri: uri,
        balance_after_usd_micros: published.balance_after_usd_micros,
    })
}
