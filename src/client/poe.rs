//! The `client.poe.*` namespace: the mutating `/api/v1/poe/*` surface.
//!
//! Low-level wrappers:
//!
//! - `POST /api/v1/poe/quote` — lock a USD price for a publish.
//! - `POST /api/v1/poe/uploads` — multipart binary upload to a storage backend.
//! - `POST /api/v1/poe/publish` — submit one finalised record.
//! - `POST /api/v1/poe/publish-batch` — submit 1..50 finalised records.
//!
//! Plus the high-level helpers ([`publish_content`](PoeNamespace::publish_content)
//! and siblings) that compose hashing, sealing, Merkle commitment, optional
//! signing, uploads, and publish into a single call.

use crate::client::http::{
    decode, json_headers, multipart_headers, send, ClientError, NamespaceConfig,
};
use crate::client::publish::{
    publish_content, publish_merkle, publish_prehashed, publish_sealed, PublishHelperError,
};
use crate::client::resumable::{upload_resumable, ResumableUploadError};
use crate::client::transport::{MultipartField, RequestBody};
use crate::client::types::{
    PublishBatchInput, PublishBatchResponse, PublishContentInput, PublishInput, PublishMerkleInput,
    PublishMerkleResponse, PublishPrehashedInput, PublishResponse, PublishSealedInput, QuoteInput,
    QuoteResponse, ResumableUploadInput, ResumableUploadResult, UploadsInput, UploadsResponse,
};
use crate::verifier::fetch::HttpMethod;

/// The `client.poe.*` namespace.
pub struct PoeNamespace<'t> {
    config: NamespaceConfig<'t>,
}

impl<'t> PoeNamespace<'t> {
    /// Construct the namespace over a resolved config.
    #[must_use]
    pub fn new(config: NamespaceConfig<'t>) -> Self {
        Self { config }
    }

    /// Request an opaque price lock for an upcoming `/publish` call.
    ///
    /// The gateway prices the described publish from the supplied byte counts,
    /// records the lock, and returns a sealed price token: `quote_id`, the total
    /// `amount` in `currency`, and an `expires_at`. The gateway's pricing
    /// internals are deliberately NOT part of the response. Pass the returned
    /// `quote_id` to a publish call.
    ///
    /// # Errors
    ///
    /// Returns a typed [`ClientError`] on any non-2xx response (e.g.
    /// [`HttpErrorKind::ServiceUnavailable`](crate::client::HttpErrorKind::ServiceUnavailable)
    /// when the gateway cannot price the quote).
    pub fn quote(&self, input: &QuoteInput) -> Result<QuoteResponse, ClientError> {
        let body = serde_json::json!({
            "record_bytes": input.record_bytes,
            "recipient_count": input.recipient_count,
            "file_bytes_total": input.file_bytes_total,
        });
        let url = format!("{}/api/v1/poe/quote", self.config.base_url);
        let headers = json_headers(self.config.api_key.as_deref(), None);
        let response = send(
            self.config.transport,
            &url,
            HttpMethod::Post,
            &headers,
            &RequestBody::Json(serde_json::to_string(&body).expect("quote body serialises")),
        )?;
        decode(&response.body)
    }

    /// Upload 1..32 binary files to a storage backend.
    ///
    /// Returns one entry per file — successful entries carry the URI + content
    /// hash, failed entries carry a per-file error so the caller can retry just
    /// the failed indices. Per-file failures inside a 200 are NOT raised here
    /// (the high-level helpers escalate them).
    ///
    /// # Errors
    ///
    /// Returns a typed [`ClientError`] on an HTTP-level failure (auth, rate
    /// limit, malformed request).
    pub fn uploads(&self, input: &UploadsInput) -> Result<UploadsResponse, ClientError> {
        let mut fields = vec![MultipartField {
            name: "target".to_string(),
            filename: None,
            content_type: None,
            value: input.target.as_bytes().to_vec(),
        }];
        for (idx, bytes) in input.data.iter().enumerate() {
            fields.push(MultipartField {
                name: format!("file_{idx}"),
                filename: Some(format!("file_{idx}.bin")),
                content_type: Some("application/octet-stream".to_string()),
                value: bytes.clone(),
            });
        }
        let url = format!("{}/api/v1/poe/uploads", self.config.base_url);
        let headers = multipart_headers(
            self.config.api_key.as_deref(),
            input.idempotency_key.as_deref(),
        );
        let response = send(
            self.config.transport,
            &url,
            HttpMethod::Post,
            &headers,
            &RequestBody::Multipart(fields),
        )?;
        decode(&response.body)
    }

    /// Upload one blob, automatically choosing the single-shot or resumable
    /// (chunked) path by size.
    ///
    /// A source at or below the threshold (default 48 MiB) rides the existing
    /// single-shot [`uploads`](Self::uploads) path unchanged. A larger source
    /// runs the content-addressed session flow: it declares the whole-file
    /// SHA-256 + size up front (unlocking dedup + affordability before any bytes
    /// flow), `PUT`s each chunk under its own integrity digest, and `complete`s
    /// the session, which assembles the file and hands it into the gateway's
    /// normal storage pipeline. The whole-file hash is streamed, so a multi-GB
    /// source is never buffered in memory.
    ///
    /// Resume an interrupted upload by passing the original `session_id` in
    /// [`ResumableUploadInput::resume_session_id`]: the helper fetches the
    /// session, re-sends only the chunks the server is still missing, and
    /// completes.
    ///
    /// The threshold and the client's intended chunk size are both options
    /// defaulting to 48 MiB (comfortably under the ~100 MB body cap a CDN/proxy
    /// commonly imposes); the server's authoritative `max_chunk_bytes` from the
    /// create response always clamps the effective chunk size down when it is
    /// tighter. Chunks are sent sequentially with per-chunk retry; see the module
    /// docs for the rationale.
    ///
    /// # Errors
    ///
    /// Returns [`ResumableUploadError`] on a read failure, a create-time funding
    /// rejection, a terminal upload failure, a malformed response, or an
    /// HTTP/transport error.
    pub fn upload_resumable(
        &self,
        input: &ResumableUploadInput,
    ) -> Result<ResumableUploadResult, ResumableUploadError> {
        upload_resumable(&self.config, input)
    }

    /// Submit one finalised canonical-CBOR record.
    ///
    /// Returns 202 (`dedup_hit: false`) on freshly enqueued records, or 200
    /// (`dedup_hit: true`) when the same record bytes were previously submitted
    /// by this account.
    ///
    /// # Errors
    ///
    /// Returns a typed [`ClientError`] on any non-2xx response.
    pub fn publish(&self, input: &PublishInput) -> Result<PublishResponse, ClientError> {
        let mut body = serde_json::Map::new();
        body.insert(
            "record".to_string(),
            serde_json::Value::String(hex::encode(&input.record)),
        );
        body.insert(
            "quote_id".to_string(),
            serde_json::Value::String(input.quote_id.clone()),
        );
        if let Some(sigs) = &input.signatures {
            body.insert("signatures".to_string(), signatures_to_json(sigs));
        }
        let url = format!("{}/api/v1/poe/publish", self.config.base_url);
        let headers = json_headers(
            self.config.api_key.as_deref(),
            input.idempotency_key.as_deref(),
        );
        let response = send(
            self.config.transport,
            &url,
            HttpMethod::Post,
            &headers,
            &RequestBody::Json(
                serde_json::to_string(&serde_json::Value::Object(body))
                    .expect("publish body serialises"),
            ),
        )?;
        let dedup_hit = response.status == 200;
        let mut parsed: PublishResponse = decode(&response.body)?;
        parsed.dedup_hit = dedup_hit;
        Ok(parsed)
    }

    /// Submit 1..50 finalised records as independent transactions.
    ///
    /// Each entry carries its own `quote_id`. Returns 200 with `results[]` —
    /// per-record errors land alongside successes without rolling back.
    ///
    /// # Errors
    ///
    /// Returns a typed [`ClientError`] on any non-2xx response (e.g.
    /// [`HttpErrorKind::BatchEmpty`](crate::client::HttpErrorKind::BatchEmpty) /
    /// [`HttpErrorKind::BatchTooLarge`](crate::client::HttpErrorKind::BatchTooLarge)).
    pub fn publish_batch(
        &self,
        input: &PublishBatchInput,
    ) -> Result<PublishBatchResponse, ClientError> {
        let records: Vec<serde_json::Value> = input
            .records
            .iter()
            .map(|r| {
                let mut entry = serde_json::Map::new();
                entry.insert(
                    "record".to_string(),
                    serde_json::Value::String(hex::encode(&r.record)),
                );
                entry.insert(
                    "quote_id".to_string(),
                    serde_json::Value::String(r.quote_id.clone()),
                );
                if let Some(sigs) = &r.signatures {
                    entry.insert("signatures".to_string(), signatures_to_json(sigs));
                }
                serde_json::Value::Object(entry)
            })
            .collect();
        let body = serde_json::json!({ "records": records });
        let url = format!("{}/api/v1/poe/publish-batch", self.config.base_url);
        let headers = json_headers(
            self.config.api_key.as_deref(),
            input.idempotency_key.as_deref(),
        );
        let response = send(
            self.config.transport,
            &url,
            HttpMethod::Post,
            &headers,
            &RequestBody::Json(serde_json::to_string(&body).expect("batch body serialises")),
        )?;
        decode(&response.body)
    }

    /// High-level hash-only publish: hash the content, build a single-item
    /// record, optionally sign, and submit. No storage round-trip.
    ///
    /// # Errors
    ///
    /// Returns [`PublishHelperError`] on validation, signer, or HTTP failure.
    pub fn publish_content(
        &self,
        input: &PublishContentInput<'_>,
    ) -> Result<PublishResponse, PublishHelperError> {
        publish_content(&self.config, input)
    }

    /// High-level publish from a precomputed digest.
    ///
    /// # Errors
    ///
    /// Returns [`PublishHelperError`] on validation, signer, or HTTP failure.
    pub fn publish_prehashed(
        &self,
        input: &PublishPrehashedInput<'_>,
    ) -> Result<PublishResponse, PublishHelperError> {
        publish_prehashed(&self.config, input)
    }

    /// High-level sealed-PoE publish: encrypt, upload, and submit.
    ///
    /// # Errors
    ///
    /// Returns [`PublishHelperError`] on validation, crypto, signer,
    /// partial-upload, or HTTP failure.
    pub fn publish_sealed(
        &self,
        input: &PublishSealedInput<'_>,
    ) -> Result<PublishResponse, PublishHelperError> {
        publish_sealed(&self.config, input)
    }

    /// High-level Merkle-batch publish: commit N leaves under one root, upload
    /// the leaves-list, and submit.
    ///
    /// # Errors
    ///
    /// Returns [`PublishHelperError`] on validation, crypto, signer,
    /// partial-upload, or HTTP failure.
    pub fn publish_merkle(
        &self,
        input: &PublishMerkleInput<'_>,
    ) -> Result<PublishMerkleResponse, PublishHelperError> {
        publish_merkle(&self.config, input)
    }
}

/// Lower the path-2 wallet signature sidecars to their JSON wire shape.
fn signatures_to_json(sigs: &[crate::client::types::RecordSignature]) -> serde_json::Value {
    serde_json::Value::Array(
        sigs.iter()
            .map(|s| {
                let mut map = serde_json::Map::new();
                map.insert(
                    "cose_sign1".to_string(),
                    serde_json::Value::String(s.cose_sign1.clone()),
                );
                if let Some(key) = &s.cose_key {
                    map.insert(
                        "cose_key".to_string(),
                        serde_json::Value::String(key.clone()),
                    );
                }
                serde_json::Value::Object(map)
            })
            .collect(),
    )
}
