//! Request and response shapes for the gateway `/api/v1/*` surface.
//!
//! Wire fields stay snake_case so JSON round-trips without translation; the SDK
//! helper structs use Rust idiom. Money crosses the wire as decimal strings
//! (USD micro-cents, 1 USD = 1,000,000 micros) so a caller can promote to an
//! arbitrary-precision integer at the application boundary without losing
//! precision to a float.

use serde::Deserialize;

/// A Label 309 hash algorithm the high-level publish helpers support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedHashAlg {
    /// SHA-256 (`sha2-256`).
    Sha2_256,
    /// BLAKE2b-256 (`blake2b-256`).
    Blake2b256,
}

impl SupportedHashAlg {
    /// The on-wire algorithm identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            SupportedHashAlg::Sha2_256 => "sha2-256",
            SupportedHashAlg::Blake2b256 => "blake2b-256",
        }
    }
}

/// The KEM a sealed-PoE envelope is built under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedKemChoice {
    /// Classical age-style ECIES over X25519 (32-byte recipient keys).
    X25519,
    /// X-Wing hybrid ML-KEM-768 + X25519 (1216-byte recipient keys); the
    /// post-quantum-safe default.
    Mlkem768X25519,
}

/// The lifecycle status of a published PoE.
pub type PoeStatus = String;

/// The conformance profile a published record satisfies.
pub type ConformanceProfile = String;

// ---------------------------------------------------------------------------
// POST /api/v1/poe/quote
// ---------------------------------------------------------------------------

/// Input to `client.poe.quote(...)`: the byte counts the server prices against.
#[derive(Debug, Clone, Copy)]
pub struct QuoteInput {
    /// Canonical-CBOR record length in bytes (header + items).
    pub record_bytes: u64,
    /// Number of sealed-PoE recipients (each adds an envelope slot).
    pub recipient_count: u64,
    /// Sum of all file bytes uploaded for this record (`0` for hash-only).
    pub file_bytes_total: u64,
}

/// An opaque price lock returned by `POST /api/v1/poe/quote`.
///
/// It is a sealed price token, not a pricing breakdown: pass `quote_id` to
/// `/publish` and surface `amount` / `currency` / `expires_at` to the user. The
/// gateway's pricing internals (FX, margins, per-component costs) are not
/// exposed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct QuoteResponse {
    /// Opaque id of the persisted price lock; pass to `/publish`.
    pub quote_id: String,
    /// Total locked price, as a decimal string (promote to an arbitrary-precision
    /// integer at the application boundary as needed).
    pub amount: String,
    /// Currency the `amount` is denominated in (e.g. ISO 4217 `USD`).
    pub currency: String,
    /// ISO 8601 expiry timestamp after which the gateway rejects the quote.
    pub expires_at: String,
}

// ---------------------------------------------------------------------------
// POST /api/v1/poe/uploads
// ---------------------------------------------------------------------------

/// Input to `client.poe.uploads(...)`: a storage target and 1..32 file blobs.
#[derive(Debug, Clone)]
pub struct UploadsInput {
    /// The storage backend (`arweave`).
    pub target: String,
    /// The file blobs; position `i` lands on the response as `uploads[i]`.
    pub data: Vec<Vec<u8>>,
    /// Optional idempotency key.
    pub idempotency_key: Option<String>,
}

/// A single upload outcome entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum UploadEntry {
    /// A successful upload: the stored URI plus content hash and byte count.
    Success {
        /// The position of the file in the request.
        idx: u64,
        /// Always `true`.
        ok: bool,
        /// The resulting storage URI (e.g. `ar://<tx>`).
        uri: String,
        /// The SHA-256 of the stored bytes (lowercase hex).
        sha256: String,
        /// The number of stored bytes.
        bytes: u64,
    },
    /// A failed upload: the per-file error code and detail.
    Failure {
        /// The position of the file in the request.
        idx: u64,
        /// Always `false`.
        ok: bool,
        /// The per-file error.
        error: UploadError,
    },
}

impl UploadEntry {
    /// Whether this entry succeeded.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(self, UploadEntry::Success { .. })
    }

    /// The `idx` of this entry.
    #[must_use]
    pub fn idx(&self) -> u64 {
        match self {
            UploadEntry::Success { idx, .. } | UploadEntry::Failure { idx, .. } => *idx,
        }
    }
}

/// A per-file upload error.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct UploadError {
    /// Stable lowercase-kebab error code.
    pub code: String,
    /// Human-readable detail.
    pub detail: String,
}

/// The response to `client.poe.uploads(...)`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct UploadsResponse {
    /// One entry per uploaded file, in request order.
    pub uploads: Vec<UploadEntry>,
}

// ---------------------------------------------------------------------------
// POST /api/v1/poe/publish
// ---------------------------------------------------------------------------

/// A path-2 CIP-30 wallet signature sidecar for the `/publish` `signatures`
/// parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordSignature {
    /// The COSE_Sign1 hex.
    pub cose_sign1: String,
    /// The optional `cbor<COSE_Key>` sidecar hex.
    pub cose_key: Option<String>,
}

/// Input to the low-level `client.poe.publish(...)`.
#[derive(Debug, Clone)]
pub struct PublishInput {
    /// The finalised canonical-CBOR record bytes.
    pub record: Vec<u8>,
    /// The quote id returned by `/poe/quote`.
    pub quote_id: String,
    /// Optional path-2 wallet signature sidecars.
    pub signatures: Option<Vec<RecordSignature>>,
    /// Optional idempotency key.
    pub idempotency_key: Option<String>,
}

/// A per-item projection on a publish response.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PoeItemResponse {
    /// The item index.
    pub item_idx: u64,
    /// Hash map: algorithm identifier → lowercase-hex digest.
    pub hashes: std::collections::BTreeMap<String, String>,
    /// Storage URIs, when present.
    pub uris: Option<Vec<String>>,
    /// The sealed envelope projection, when present.
    pub enc: Option<serde_json::Value>,
}

/// The response to `client.poe.publish(...)`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PublishResponse {
    /// Prefixed id (`poe_<26-char-crockford>`) of the inserted record row.
    pub id: String,
    /// The Cardano transaction hash, once known.
    pub tx_hash: Option<String>,
    /// The lifecycle status.
    pub status: PoeStatus,
    /// The number of content items in the record.
    pub items_count: u64,
    /// Whether the record carries a record-level signature.
    pub signed: bool,
    /// Whether the record is a sealed PoE.
    pub sealed: bool,
    /// The per-item projections.
    pub items: Vec<PoeItemResponse>,
    /// The satisfied conformance profile.
    pub conformance_profile: ConformanceProfile,
    /// Account balance after the debit (decimal string).
    pub balance_after_usd_micros: String,
    /// `true` when the server returned 200 (dedup hit) rather than 202 (fresh).
    /// Populated by the client from the HTTP status, not the body.
    #[serde(default)]
    pub dedup_hit: bool,
}

// ---------------------------------------------------------------------------
// POST /api/v1/poe/publish-batch
// ---------------------------------------------------------------------------

/// A single entry in a publish-batch request.
#[derive(Debug, Clone)]
pub struct PublishBatchEntry {
    /// The finalised canonical-CBOR record bytes.
    pub record: Vec<u8>,
    /// The quote id scoped to this record.
    pub quote_id: String,
    /// Optional path-2 wallet signature sidecars.
    pub signatures: Option<Vec<RecordSignature>>,
}

/// Input to `client.poe.publish_batch(...)`.
#[derive(Debug, Clone)]
pub struct PublishBatchInput {
    /// The 1..50 records to submit.
    pub records: Vec<PublishBatchEntry>,
    /// Optional idempotency key.
    pub idempotency_key: Option<String>,
}

/// A successful per-record entry inside a publish-batch result.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PublishBatchSuccessEntry {
    /// The index of the record in the request.
    pub record_idx: u64,
    /// The inserted record id.
    pub id: String,
    /// The Cardano transaction hash, once known.
    pub tx_hash: Option<String>,
    /// The lifecycle status.
    pub status: PoeStatus,
    /// The number of content items in the record.
    pub items_count: u64,
    /// Whether the record is signed.
    pub signed: bool,
    /// Whether the record is sealed.
    pub sealed: bool,
    /// The per-item projections.
    pub items: Vec<PoeItemResponse>,
    /// The satisfied conformance profile.
    pub conformance_profile: ConformanceProfile,
}

/// A per-record failure body inside a publish-batch result.
///
/// Carries only the body-level RFC 7807 fields, since the entry is already
/// nested inside a 200 response (no per-row `type` / `status` / `trace_id`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PublishBatchFailureError {
    /// Stable lowercase-kebab error code.
    pub code: String,
    /// Human-readable detail.
    pub detail: String,
    /// Per-field validation errors, when present.
    pub errors: Option<Vec<crate::client::errors::ProblemErrorEntry>>,
    /// Extension members, when present.
    pub extensions: Option<serde_json::Map<String, serde_json::Value>>,
}

/// A per-record failure entry inside a publish-batch result.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PublishBatchFailureEntry {
    /// The index of the record in the request.
    pub record_idx: u64,
    /// The per-record error.
    pub error: PublishBatchFailureError,
}

/// One result entry in a publish-batch response: success or per-record failure.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum PublishBatchResultEntry {
    /// A successful per-record entry.
    Success(PublishBatchSuccessEntry),
    /// A per-record failure entry.
    Failure(PublishBatchFailureEntry),
}

/// The response to `client.poe.publish_batch(...)`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PublishBatchResponse {
    /// One result per submitted record (successes alongside failures).
    pub results: Vec<PublishBatchResultEntry>,
    /// Aggregate balance after every successful debit (decimal string).
    pub balance_after_usd_micros: String,
}

// ---------------------------------------------------------------------------
// GET /api/v1/records/{tx_hash}
// ---------------------------------------------------------------------------

/// A single record resource projection.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RecordResource {
    /// The Cardano transaction hash.
    pub tx_hash: String,
    /// The chain-derived lifecycle status.
    pub status: Option<String>,
    /// The block height, when anchored.
    pub block_height: Option<u64>,
    /// The block time, when anchored.
    pub block_time: Option<String>,
    /// The confirmation depth.
    pub num_confirmations: u64,
    /// The record scheme (`0` core, `1` sealed, `2` …).
    pub scheme: u8,
    /// The number of content items.
    pub item_count: u64,
    /// The record-level Ed25519 signer (lowercase hex), when signed.
    pub signer_ed25519: Option<String>,
    /// Base64-encoded canonical-CBOR record bytes.
    pub metadata_cbor_base64: String,
    /// Owner-only account id (present only for the row's authenticated owner).
    pub account_id: Option<String>,
}

// ---------------------------------------------------------------------------
// GET /api/v1/account/balance
// ---------------------------------------------------------------------------

/// The caller's current prepaid USD balance.
///
/// `balance_usd_micros` is the balance in USD micro-cents, carried as a decimal
/// `String` (never a numeric type) so the bigint value survives without
/// precision loss. An account with no ledger activity yet reads `"0"`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AccountBalance {
    /// The current USD balance in micro-cents, as a decimal string.
    pub balance_usd_micros: String,
}

// ---------------------------------------------------------------------------
// POST /api/v1/records/{tx_hash}/verify
// ---------------------------------------------------------------------------

/// A single decryption request for `client.records.verify(...)`.
#[derive(Debug, Clone)]
pub struct PoeVerifyDecryption {
    /// The item index to decrypt.
    pub item_idx: u64,
    /// The recipient X25519/X-Wing secret key (lowercase hex), for slot
    /// decryption.
    pub recipient_secret_key: Option<String>,
    /// The passphrase, for passphrase decryption.
    pub passphrase: Option<String>,
}

/// Input to `client.records.verify(...)`.
#[derive(Debug, Clone, Default)]
pub struct PoeVerifyInput {
    /// Toggle URI hash-equivalence checks.
    pub verify_uris: Option<bool>,
    /// Per-item decryption requests.
    pub decryption: Option<Vec<PoeVerifyDecryption>>,
}

// ---------------------------------------------------------------------------
// GET /api/v1/records — paginated record list (client.records.list)
// ---------------------------------------------------------------------------

/// Input to `client.records.list(...)`.
///
/// The optional `sealed` filter narrows the page to sealed records addressed to
/// the authenticated caller (the gateway resolves "addressed to me" from the
/// identity behind the bearer token); omitting it lists every record the caller
/// may read.
#[derive(Debug, Clone, Default)]
pub struct RecordsListInput {
    /// Opaque pagination cursor from a prior page.
    pub cursor: Option<String>,
    /// Page size (the gateway may clamp).
    pub limit: Option<u64>,
    /// When `Some(true)`, restrict the page to sealed records addressed to the
    /// authenticated caller. When `None`, list every record the caller may read.
    pub sealed: Option<bool>,
}

/// The response to `client.records.list(...)`.
///
/// Each `data[]` entry is the same [`RecordResource`] projection
/// `records.get` returns. Page with `cursor = next_cursor` until `has_more` is
/// `false`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RecordsListResponse {
    /// Always `"list"`.
    pub object: String,
    /// The record resources on this page.
    pub data: Vec<RecordResource>,
    /// Whether more pages remain.
    pub has_more: bool,
    /// The opaque cursor for the next page, when present.
    pub next_cursor: Option<String>,
    /// The canonical URL of this list resource.
    pub url: String,
    /// The chain tip block height observed when this page was served, used to
    /// compute confirmation depth during a sealed-record sync.
    ///
    /// Optional: a gateway that reports it (JSON key `tip_block_height`)
    /// populates confirmation data directly; otherwise the SDK derives it from
    /// the page rows as `max(block_height + num_confirmations - 1)`, falling
    /// back to `None` for an empty page or rows without a block height.
    #[serde(default)]
    pub tip_block_height: Option<u64>,
}

// ---------------------------------------------------------------------------
// High-level publish helper inputs / responses
// ---------------------------------------------------------------------------

/// Input to `client.poe.publish_content(...)` — hash-only.
pub struct PublishContentInput<'a> {
    /// The content bytes to anchor.
    pub content: Vec<u8>,
    /// The quote id returned by `/poe/quote`.
    pub quote_id: String,
    /// The hash algorithm (defaults to SHA-256).
    pub hash_alg: Option<SupportedHashAlg>,
    /// The optional record-level signer.
    pub signer: Option<&'a dyn crate::client::publish::Signer>,
    /// Optional idempotency key.
    pub idempotency_key: Option<String>,
}

/// Input to `client.poe.publish_prehashed(...)` — caller already holds digests.
pub struct PublishPrehashedInput<'a> {
    /// Algorithm identifier → lowercase-hex digest. At least one is required.
    pub hashes: Vec<(SupportedHashAlg, String)>,
    /// The quote id returned by `/poe/quote`.
    pub quote_id: String,
    /// The optional record-level signer.
    pub signer: Option<&'a dyn crate::client::publish::Signer>,
    /// Optional idempotency key.
    pub idempotency_key: Option<String>,
}

/// Input to `client.poe.publish_sealed(...)`.
pub struct PublishSealedInput<'a> {
    /// The content bytes to seal.
    pub content: Vec<u8>,
    /// The recipient public keys (32 B for x25519, 1216 B for the hybrid KEM).
    pub recipients: Vec<Vec<u8>>,
    /// The quote id returned by `/poe/quote`.
    pub quote_id: String,
    /// The plaintext-bind hash algorithm (defaults to SHA-256).
    pub hash_alg: Option<SupportedHashAlg>,
    /// The KEM the envelope is built under (defaults to the X-Wing hybrid).
    pub kem: Option<SealedKemChoice>,
    /// The optional record-level signer.
    pub signer: Option<&'a dyn crate::client::publish::Signer>,
    /// Optional idempotency key.
    pub idempotency_key: Option<String>,
}

/// A leaf hash for `client.poe.publish_merkle(...)`: raw bytes or hex.
#[derive(Debug, Clone)]
pub enum MerkleLeaf {
    /// A raw 32-byte digest.
    Bytes(Vec<u8>),
    /// A 64-character hex digest.
    Hex(String),
}

/// Input to `client.poe.publish_merkle(...)`.
pub struct PublishMerkleInput<'a> {
    /// The leaf hashes (raw 32-byte digests or hex).
    pub leaves: Vec<MerkleLeaf>,
    /// The quote id returned by `/poe/quote`.
    pub quote_id: String,
    /// The leaf-hash algorithm (only SHA-256 is supported).
    pub hash_alg: Option<SupportedHashAlg>,
    /// The optional record-level signer.
    pub signer: Option<&'a dyn crate::client::publish::Signer>,
    /// Optional idempotency key.
    pub idempotency_key: Option<String>,
}

/// The response to `client.poe.publish_merkle(...)`.
#[derive(Debug, Clone, PartialEq)]
pub struct PublishMerkleResponse {
    /// The inserted record id.
    pub id: String,
    /// The Cardano transaction hash, once known.
    pub tx_hash: Option<String>,
    /// The lifecycle status.
    pub status: PoeStatus,
    /// The Merkle root (lowercase hex).
    pub root: String,
    /// The number of committed leaves.
    pub leaf_count: u64,
    /// The `ar://<tx>` URI of the uploaded leaves-list.
    pub ar_uri: String,
    /// Account balance after the debit (decimal string).
    pub balance_after_usd_micros: String,
}
