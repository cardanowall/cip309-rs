//! The resumable / chunked upload helper.
//!
//! [`upload_resumable`] is the additive, threshold-gated counterpart to the
//! single-shot [`uploads`](crate::client::PoeNamespace::uploads). It exists for
//! one reason: a single request body is commonly capped at ~100 MB by a CDN or
//! reverse proxy, so a file larger than that cannot ride the single-shot
//! multipart `POST`. The helper splits a large file into chunks the gateway
//! reassembles, and resumes a dropped transfer instead of restarting it.
//!
//! Path selection is by size:
//!
//! - A source at or below the threshold (default
//!   [`DEFAULT_RESUMABLE_THRESHOLD_BYTES`]) rides the existing single-shot
//!   `uploads` path unchanged — the resumable helper adds nothing and changes
//!   nothing for small files.
//! - A larger source runs the content-addressed session flow: declare the
//!   whole-file SHA-256 + size up front (which unlocks dedup and affordability
//!   before any bytes flow), `PUT` each chunk under its own integrity digest, then
//!   `complete` to assemble + hand the file into the gateway's normal storage
//!   pipeline.
//!
//! ## Whole-file hashing is streamed
//!
//! The declared digest is computed in one bounded-memory pass over the source so
//! a multi-GB file is never held in memory. A path source is read in fixed-size
//! reads; an in-memory source hashes its slice directly.
//!
//! ## Chunks are sent sequentially
//!
//! The gateway's positional-write protocol permits chunks to arrive out of order
//! and in parallel, and a browser is expected to run a few parallel `PUT`s to
//! saturate its uplink. This SDK is deliberately blocking and routes every
//! request through one shared, non-`Send`/`Sync` egress (the same single
//! outbound path the verifier uses, so the deny-host / SSRF / protocol guards
//! apply uniformly). Spawning chunk uploads across threads would force a
//! `Send + Sync` bound onto the transport trait, a breaking change rippling
//! through every namespace and the test stubs, for a throughput win the blocking
//! posture does not target. So chunks are sent **one at a time**, each retried on
//! a transient failure. The resilience the protocol promises — never re-sending a
//! received chunk, resuming a dropped transfer from the `missing` set — is fully
//! preserved; only the within-session parallelism is dropped, which a caller that
//! needs it can recover by driving the wire protocol directly.

use crate::client::http::{
    decode, into_http_error, json_headers, send, send_raw, ClientError, NamespaceConfig,
};
use crate::client::transport::{MultipartField, RequestBody};
use crate::client::types::{
    ResumableSource, ResumableUploadInput, ResumableUploadResult, UploadAttemptStatus, UploadEntry,
    UploadError, UploadSessionChunkAck, UploadSessionCreated, UploadSessionDeduplicated,
    UploadSessionStatus, UploadsResponse,
};
use crate::verifier::fetch::HttpMethod;
use sha2::{Digest, Sha256};

/// The default switch-to-chunked threshold: 48 MiB.
///
/// Comfortably under the ~100 MB single-request body cap a CDN/proxy commonly
/// imposes, with ample margin for multipart and transport overhead on the
/// single-shot path.
pub const DEFAULT_RESUMABLE_THRESHOLD_BYTES: u64 = 50_331_648;

/// The default chunk size: 48 MiB.
///
/// The server's authoritative `max_chunk_bytes` (from the create response) always
/// clamps this down further when it is tighter; this default is the client's
/// request, never an override of the server ceiling.
pub const DEFAULT_RESUMABLE_CHUNK_BYTES: u64 = 50_331_648;

/// The number of times a single chunk `PUT` is retried on a transient failure
/// before the upload gives up. A re-`PUT` of the same bytes is idempotent on the
/// server, so a retry is always safe.
const CHUNK_RETRY_ATTEMPTS: u32 = 3;

/// The interval between attempt-status polls.
///
/// A real Turbo/Arweave commit stays `reserved` for seconds, so the helper must
/// pause between polls rather than spin: a tight loop would burn the entire
/// budget in milliseconds and reject a valid upload that simply has not committed
/// yet. The blocking egress serialises the requests, so a plain thread-sleep is
/// the right pacing primitive here.
const ATTEMPT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(1000);

/// The total wall-clock budget for polling an accepted attempt to a terminal
/// state. Only after this genuinely elapses without reaching `committed` or
/// `released` does the helper give up. At [`ATTEMPT_POLL_INTERVAL`] this allows
/// ~600 polls, matching the long-running-commit window the storage backend can
/// take to durably persist a large data item.
const ATTEMPT_POLL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// The number of times `complete` is re-attempted after a `409 incomplete-upload`.
/// Each retry re-reads the session, re-sends the reported missing chunks, then
/// completes again. A bounded budget avoids an unbounded resend loop against a
/// gateway that keeps reporting an incomplete upload despite resends.
const COMPLETE_RETRY_ATTEMPTS: u32 = 2;

/// The error a resumable upload returns.
#[derive(Debug, thiserror::Error)]
pub enum ResumableUploadError {
    /// An HTTP/transport error from the gateway.
    #[error(transparent)]
    Http(#[from] ClientError),
    /// The source could not be read (a missing path, a permissions failure, a
    /// truncated read).
    #[error("upload source could not be read: {0}")]
    Source(String),
    /// The source is shorter than the server-declared chunk grid: a chunk read
    /// fell at or past the end of the local bytes. This happens on a resume whose
    /// in-memory source no longer covers the originally declared `total_bytes`
    /// (e.g. a truncated buffer). It is recoverable for the caller to handle, not
    /// a reason to panic the process.
    #[error("upload source is shorter than the declared grid: chunk {index} at offset {offset} is past the {source_len}-byte source")]
    SourceTruncated {
        /// The chunk index that could not be read.
        index: u32,
        /// The byte offset the chunk grid placed this index at.
        offset: u64,
        /// The actual length of the local source.
        source_len: u64,
    },
    /// The account cannot fund the chargeable bytes (the create-time `402`). The
    /// verbatim gateway problem document is carried for the caller to surface.
    #[error("insufficient funds for the upload: {0}")]
    InsufficientFunds(Box<crate::client::errors::Label309HttpError>),
    /// The upload reached a terminal failure (the gateway released the attempt
    /// without committing the bytes).
    #[error("the upload failed: {0}")]
    Failed(String),
    /// The single-shot path returned a per-file rejection. The verbatim per-file
    /// `code` + `detail` are carried so the publish helpers can re-surface the
    /// exact diagnostic the single-shot `/uploads` route emitted, rather than a
    /// flattened synthetic one.
    #[error("the upload was rejected: {}: {}", .0.code, .0.detail)]
    UploadRejected(UploadError),
    /// A response body could not be parsed into its expected shape.
    #[error("failed to parse a gateway response: {0}")]
    Decode(String),
    /// The protocol reached a state the helper cannot make progress from (e.g.
    /// `complete` returned neither a URI nor an attempt to poll).
    #[error("the upload protocol reached an unexpected state: {0}")]
    Protocol(String),
}

/// Drive an upload, choosing the single-shot or chunked path by size.
///
/// # Errors
///
/// Returns [`ResumableUploadError`] on a read failure, a funding rejection, a
/// terminal upload failure, a malformed response, or an HTTP/transport error.
pub fn upload_resumable(
    config: &NamespaceConfig<'_>,
    input: &ResumableUploadInput,
) -> Result<ResumableUploadResult, ResumableUploadError> {
    let threshold = input
        .threshold_bytes
        .unwrap_or(DEFAULT_RESUMABLE_THRESHOLD_BYTES);

    // A resume is always a chunked operation regardless of size: the session
    // already exists, so honour it.
    if input.resume_session_id.is_none() {
        let total_bytes = source_len(&input.source)?;
        if total_bytes <= threshold {
            return single_shot(config, input);
        }
    }

    chunked(config, input)
}

/// The single-shot path: the same multipart `POST /uploads` the small-file
/// callers already use, projected onto the resumable result.
fn single_shot(
    config: &NamespaceConfig<'_>,
    input: &ResumableUploadInput,
) -> Result<ResumableUploadResult, ResumableUploadError> {
    let bytes = read_source(&input.source)?;
    let mut fields = vec![MultipartField {
        name: "target".to_string(),
        filename: None,
        content_type: None,
        value: input.target.as_bytes().to_vec(),
    }];
    fields.push(MultipartField {
        name: "file_0".to_string(),
        filename: Some("file_0.bin".to_string()),
        content_type: Some(
            input
                .content_type
                .clone()
                .unwrap_or_else(|| "application/octet-stream".to_string()),
        ),
        value: bytes,
    });
    let url = format!("{}/api/v1/poe/uploads", config.base_url);
    let headers = crate::client::http::multipart_headers(
        config.api_key.as_deref(),
        input.idempotency_key.as_deref(),
    );
    let response = send(
        config.transport,
        &url,
        HttpMethod::Post,
        &headers,
        &RequestBody::Multipart(fields),
    )?;
    let parsed: UploadsResponse = decode(&response.body)?;
    let entry = parsed.uploads.into_iter().next().ok_or_else(|| {
        ResumableUploadError::Protocol("the single-shot upload returned no entry".into())
    })?;
    match entry {
        UploadEntry::Success {
            uri, sha256, bytes, ..
        } => Ok(ResumableUploadResult {
            uri,
            sha256: Some(sha256),
            bytes: Some(bytes),
            charged_usd_micros: None,
            deduplicated: false,
            session_id: None,
        }),
        // Carry the per-file error verbatim so the publish helpers can re-surface
        // the original code + detail (not a flattened string).
        UploadEntry::Failure { error, .. } => Err(ResumableUploadError::UploadRejected(error)),
    }
}

/// The chunked path: create (or resume) a session, send the missing chunks, then
/// complete.
fn chunked(
    config: &NamespaceConfig<'_>,
    input: &ResumableUploadInput,
) -> Result<ResumableUploadResult, ResumableUploadError> {
    let chunk_request = input.chunk_bytes.unwrap_or(DEFAULT_RESUMABLE_CHUNK_BYTES);

    // Resolve the session: an explicit id is fetched and resumed; otherwise a
    // fresh session is created (which may short-circuit to a dedup hit and flow
    // no bytes).
    let session = match &input.resume_session_id {
        Some(sid) => {
            let status = get_status(config, sid)?;
            // A resumed session that already reached a terminal state needs no
            // further chunks: return its recorded outcome directly.
            if let Some(done) = terminal_from_status(config, &status)? {
                return Ok(done);
            }
            SessionGrid {
                session_id: status.session_id,
                chunk_bytes: status.chunk_bytes,
                chunk_count: status.chunk_count,
                // The server's declared total bounds every chunk read so the
                // final slice is exactly the remainder.
                total_bytes: status.total_bytes,
                // Adopt the server's declared digest on resume; never re-hash the
                // local source. It seeds the default completion idempotency key.
                declared_sha256_hex: status.sha256,
                missing: status.missing,
            }
        }
        None => {
            let total_bytes = source_len(&input.source)?;
            let whole_sha256 = stream_sha256(&input.source)?;
            match create_session(config, input, &whole_sha256, total_bytes, chunk_request)? {
                CreateOutcome::Deduplicated(dedup) => {
                    return Ok(ResumableUploadResult {
                        uri: dedup.uri,
                        sha256: Some(dedup.sha256),
                        bytes: Some(dedup.bytes),
                        charged_usd_micros: Some(0),
                        deduplicated: true,
                        session_id: None,
                    });
                }
                CreateOutcome::Created(created) => SessionGrid {
                    session_id: created.session_id,
                    chunk_bytes: created.chunk_bytes,
                    chunk_count: created.chunk_count,
                    // The declared total (the bytes that were hashed at create
                    // time) is authoritative for the slice math: a file that grew
                    // afterwards must not push extra bytes into the final chunk.
                    total_bytes,
                    // The digest just declared at create time; seeds the default
                    // completion idempotency key.
                    declared_sha256_hex: hex::encode(whole_sha256),
                    // A fresh create reports the empty received set; everything is
                    // missing.
                    missing: (0..created.chunk_count)
                        .filter(|i| !created.received.contains(i))
                        .collect(),
                },
            }
        }
    };

    // Send every outstanding chunk, honouring the server's authoritative
    // chunk_bytes for the slice math.
    send_missing_chunks(config, &session, &input.source, &session.missing)?;

    complete_session(
        config,
        &session,
        &input.source,
        input.idempotency_key.as_deref(),
    )
}

/// Send a set of outstanding chunk indices, bounding every read to the declared
/// total so the final chunk is exactly the remainder.
fn send_missing_chunks(
    config: &NamespaceConfig<'_>,
    session: &SessionGrid,
    source: &ResumableSource,
    missing: &[u32],
) -> Result<(), ResumableUploadError> {
    for index in missing {
        let chunk = read_chunk(source, *index, session.chunk_bytes, session.total_bytes)?;
        put_chunk_with_retry(config, &session.session_id, *index, &chunk)?;
    }
    Ok(())
}

/// The chunk grid resolved from a create or a resumed status.
struct SessionGrid {
    session_id: String,
    chunk_bytes: u64,
    #[allow(dead_code)]
    chunk_count: u32,
    /// The declared whole-file size in bytes; bounds every chunk read so a file
    /// that grew after create/hash cannot over-read the final chunk.
    total_bytes: u64,
    /// The declared whole-file SHA-256 (lowercase hex) the session is
    /// content-addressed by. Computed once on a fresh create; adopted from the
    /// server status on resume (never recomputed). It seeds the default
    /// completion idempotency key.
    declared_sha256_hex: String,
    missing: Vec<u32>,
}

/// The disposition of a session create.
enum CreateOutcome {
    /// The declared bytes were already stored; no session, no upload.
    Deduplicated(UploadSessionDeduplicated),
    /// A live session was created with its authoritative chunk grid.
    Created(UploadSessionCreated),
}

/// `POST /api/v1/poe/uploads/sessions` — create a session or short-circuit.
fn create_session(
    config: &NamespaceConfig<'_>,
    input: &ResumableUploadInput,
    whole_sha256: &[u8; 32],
    total_bytes: u64,
    chunk_request: u64,
) -> Result<CreateOutcome, ResumableUploadError> {
    let mut body = serde_json::Map::new();
    body.insert(
        "target".to_string(),
        serde_json::Value::String(input.target.clone()),
    );
    body.insert(
        "sha256".to_string(),
        serde_json::Value::String(hex::encode(whole_sha256)),
    );
    body.insert("total_bytes".to_string(), total_bytes.into());
    body.insert("chunk_bytes".to_string(), chunk_request.into());
    if let Some(ct) = &input.content_type {
        body.insert(
            "content_type".to_string(),
            serde_json::Value::String(ct.clone()),
        );
    }
    let url = format!("{}/api/v1/poe/uploads/sessions", config.base_url);
    let headers = json_headers(config.api_key.as_deref(), None);
    let response = send_raw(
        config.transport,
        &url,
        HttpMethod::Post,
        &headers,
        &RequestBody::Json(
            serde_json::to_string(&serde_json::Value::Object(body)).map_err(|e| {
                ResumableUploadError::Protocol(format!("create body did not serialise: {e}"))
            })?,
        ),
    )?;

    // 402: the account cannot fund the chargeable bytes. Surface the verbatim
    // problem so the caller can route the user to top up.
    if response.status == 402 {
        return Err(funding_error(response));
    }
    // A create dedup short-circuit is a 200 carrying `deduplicated: true`; a fresh
    // session is a 201. Any other non-2xx is a terminal error mapped the usual
    // way.
    let response = into_http_error(response)?;
    if response.status == 200 {
        let dedup: UploadSessionDeduplicated = parse(&response.body)?;
        return Ok(CreateOutcome::Deduplicated(dedup));
    }
    let created: UploadSessionCreated = parse(&response.body)?;
    Ok(CreateOutcome::Created(created))
}

/// `GET /api/v1/poe/uploads/sessions/{sid}` — the resume contract.
fn get_status(
    config: &NamespaceConfig<'_>,
    session_id: &str,
) -> Result<UploadSessionStatus, ResumableUploadError> {
    let url = format!(
        "{}/api/v1/poe/uploads/sessions/{}",
        config.base_url,
        encode_path_segment(session_id)
    );
    let headers = json_headers(config.api_key.as_deref(), None);
    let response = send(
        config.transport,
        &url,
        HttpMethod::Get,
        &headers,
        &RequestBody::None,
    )?;
    parse(&response.body)
}

/// `PUT /api/v1/poe/uploads/sessions/{sid}/chunks/{index}` with per-chunk retry.
///
/// A re-`PUT` of the same bytes is an idempotent `200` on the server, so a
/// transient failure is always safe to retry. A digest conflict (`409`) means
/// the caller is contradicting an already-received chunk and is NOT retried — it
/// surfaces as a terminal error.
fn put_chunk_with_retry(
    config: &NamespaceConfig<'_>,
    session_id: &str,
    index: u32,
    chunk: &[u8],
) -> Result<UploadSessionChunkAck, ResumableUploadError> {
    let url = format!(
        "{}/api/v1/poe/uploads/sessions/{}/chunks/{}",
        config.base_url,
        encode_path_segment(session_id),
        index
    );
    let digest = format!("sha-256={}", base64_standard(&sha256_bytes(chunk)));

    let mut last_err: Option<ResumableUploadError> = None;
    for _ in 0..CHUNK_RETRY_ATTEMPTS {
        let mut headers = json_headers(config.api_key.as_deref(), None);
        // The chunk body is raw octet-stream, not JSON; replace the JSON
        // content-type with the digest and let the transport set the binary
        // content-type.
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-type"));
        headers.push(("content-length".to_string(), chunk.len().to_string()));
        headers.push(("digest".to_string(), digest.clone()));

        let response = send_raw(
            config.transport,
            &url,
            HttpMethod::Put,
            &headers,
            &RequestBody::Bytes(chunk.to_vec()),
        )?;
        if (200..300).contains(&response.status) {
            return parse(&response.body);
        }
        // A 4xx that is the client's fault (a conflicting digest, a size
        // mismatch, an expired or vanished session) is terminal — retrying the
        // same bytes cannot fix it. A 5xx / transport hiccup is transient.
        let err: ResumableUploadError = into_http_error(response).unwrap_err().into();
        if is_terminal_chunk_error(&err) {
            return Err(err);
        }
        last_err = Some(err);
    }
    Err(last_err.unwrap_or_else(|| {
        ResumableUploadError::Protocol(format!("chunk {index} exhausted its retries"))
    }))
}

/// `POST /api/v1/poe/uploads/sessions/{sid}/complete` — finalise the session.
///
/// On `409 incomplete-upload` (a chunk that was acknowledged client-side but did
/// not durably persist on the server) the helper re-reads the session status,
/// re-sends the reported missing chunks, and retries complete, up to
/// [`COMPLETE_RETRY_ATTEMPTS`] times. This is the resume the protocol intends: an
/// incomplete upload is a transient gap to close, not a terminal error. On
/// `accepted` it polls the attempt endpoint to the terminal outcome.
fn complete_session(
    config: &NamespaceConfig<'_>,
    session: &SessionGrid,
    source: &ResumableSource,
    idempotency_key: Option<&str>,
) -> Result<ResumableUploadResult, ResumableUploadError> {
    let url = format!(
        "{}/api/v1/poe/uploads/sessions/{}/complete",
        config.base_url,
        encode_path_segment(&session.session_id)
    );
    // The completion key is the caller's promise of sameness; default it to the
    // session's declared digest so a re-invocation replays the recorded terminal
    // result. The format string MUST match the TypeScript SDK exactly, so a TS and
    // a Rust client completing the same content derive the same key.
    let default_key = default_idempotency_key(&session.declared_sha256_hex);
    let effective_key = idempotency_key.unwrap_or(&default_key);
    let headers = json_headers(config.api_key.as_deref(), Some(effective_key));

    for _ in 0..=COMPLETE_RETRY_ATTEMPTS {
        let response = send_raw(
            config.transport,
            &url,
            HttpMethod::Post,
            &headers,
            &RequestBody::Json("{}".to_string()),
        )?;

        if (200..300).contains(&response.status) {
            return complete_body_to_result(config, &session.session_id, &response.body);
        }

        let err: ResumableUploadError = into_http_error(response).unwrap_err().into();
        // A 409 incomplete-upload is the protocol's resume cue: re-read the
        // session, re-send the gaps the server still reports, then complete again.
        // Any other error is terminal here. The final iteration does not resume
        // (the budget is spent), so an upload the server keeps reporting as
        // incomplete surfaces the 409 rather than looping forever.
        if !is_incomplete_upload_error(&err) {
            return Err(err);
        }
        let status = get_status(config, &session.session_id)?;
        if status.missing.is_empty() {
            // The server has every chunk but is still racing assembly; retry
            // complete without re-sending anything.
            continue;
        }
        // Re-send only the still-missing indices, bounded by the declared total
        // exactly as the first pass was.
        send_missing_chunks(config, session, source, &status.missing)?;
    }

    // The grid is known and we re-sent every reported gap, yet the gateway kept
    // reporting an incomplete upload: surface it as a terminal failure rather than
    // an opaque retry exhaustion.
    Err(ResumableUploadError::Failed(format!(
        "session {} could not be completed after re-sending the missing chunks",
        session.session_id
    )))
}

/// Whether an error is the `409 incomplete-upload` resume cue.
fn is_incomplete_upload_error(err: &ResumableUploadError) -> bool {
    matches!(
        err,
        ResumableUploadError::Http(ClientError::Http(boxed))
            if boxed.http_status() == 409 && boxed.code() == "incomplete-upload"
    )
}

/// Project a 2xx `complete` body onto a [`ResumableUploadResult`], polling the
/// attempt endpoint when the body is an `accepted` handle rather than a terminal
/// outcome.
fn complete_body_to_result(
    config: &NamespaceConfig<'_>,
    session_id: &str,
    body: &[u8],
) -> Result<ResumableUploadResult, ResumableUploadError> {
    let value: serde_json::Value = parse(body)?;
    if let Some(uri) = value.get("uri").and_then(serde_json::Value::as_str) {
        return Ok(ResumableUploadResult {
            uri: uri.to_string(),
            sha256: value
                .get("sha256")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            bytes: value.get("bytes").and_then(serde_json::Value::as_u64),
            charged_usd_micros: value
                .get("charged_usd_micros")
                .and_then(serde_json::Value::as_u64),
            deduplicated: value
                .get("charged_usd_micros")
                .and_then(serde_json::Value::as_u64)
                == Some(0),
            session_id: Some(session_id.to_string()),
        });
    }
    if let Some(attempt_id) = value.get("attempt_id").and_then(serde_json::Value::as_str) {
        return poll_attempt(config, session_id, attempt_id);
    }
    Err(ResumableUploadError::Protocol(
        "complete returned neither a uri nor an attempt to poll".into(),
    ))
}

/// Poll `GET /api/v1/poe/uploads/attempts/{attempt_id}` to the terminal outcome.
///
/// A `committed` attempt yields the URI + charge; a `released` attempt is a
/// terminal failure. A still-`reserved` attempt is the only in-flight state: the
/// helper sleeps [`ATTEMPT_POLL_INTERVAL`] between polls and keeps polling until
/// the attempt reaches a terminal state or the [`ATTEMPT_POLL_TIMEOUT`] budget
/// genuinely elapses. A real storage commit stays reserved for seconds, so this
/// paced wait is what lets a valid accepted upload converge instead of being
/// rejected by a spin-loop the moment it is declared. Only after the wall-clock
/// budget is spent does the helper surface a timeout.
fn poll_attempt(
    config: &NamespaceConfig<'_>,
    session_id: &str,
    attempt_id: &str,
) -> Result<ResumableUploadResult, ResumableUploadError> {
    let url = format!(
        "{}/api/v1/poe/uploads/attempts/{}",
        config.base_url,
        encode_path_segment(attempt_id)
    );
    let headers = json_headers(config.api_key.as_deref(), None);
    let deadline = std::time::Instant::now() + ATTEMPT_POLL_TIMEOUT;
    loop {
        let response = send(
            config.transport,
            &url,
            HttpMethod::Get,
            &headers,
            &RequestBody::None,
        )?;
        let status: UploadAttemptStatus = parse(&response.body)?;
        match status.state.as_str() {
            "committed" => {
                let uri = status.uri.clone().ok_or_else(|| {
                    ResumableUploadError::Protocol("a committed attempt carried no uri".into())
                })?;
                return Ok(ResumableUploadResult {
                    uri,
                    sha256: Some(status.sha256),
                    bytes: Some(status.bytes),
                    charged_usd_micros: status.charged_usd_micros,
                    deduplicated: status.charged_usd_micros == Some(0),
                    session_id: Some(session_id.to_string()),
                });
            }
            "released" => {
                return Err(ResumableUploadError::Failed(
                    status
                        .reason
                        .unwrap_or_else(|| "the upload attempt was released".to_string()),
                ));
            }
            // Any non-terminal state (`reserved`, or an unknown future state)
            // keeps the wait alive until the deadline.
            _ => {}
        }
        if std::time::Instant::now() >= deadline {
            // The attempt never reached a terminal state inside the budget.
            return Err(ResumableUploadError::Failed(format!(
                "upload attempt {attempt_id} did not reach a terminal state in time (session {session_id})"
            )));
        }
        std::thread::sleep(ATTEMPT_POLL_INTERVAL);
    }
}

/// Map a terminal status (a resumed session already `completed`/`failed`) onto a
/// result; `None` when the session is still open and chunks must be sent.
fn terminal_from_status(
    config: &NamespaceConfig<'_>,
    status: &UploadSessionStatus,
) -> Result<Option<ResumableUploadResult>, ResumableUploadError> {
    match status.state.as_str() {
        "completed" => {
            let uri = status.uri.clone().ok_or_else(|| {
                ResumableUploadError::Protocol("a completed session carried no uri".into())
            })?;
            Ok(Some(ResumableUploadResult {
                uri,
                sha256: Some(status.sha256.clone()),
                bytes: Some(status.total_bytes),
                charged_usd_micros: None,
                deduplicated: false,
                session_id: Some(status.session_id.clone()),
            }))
        }
        "failed" => Err(ResumableUploadError::Failed(
            "the resumed session previously failed its integrity check".into(),
        )),
        "expired" => Err(ResumableUploadError::Failed(
            "the resumed session has expired".into(),
        )),
        "assembling" => {
            // A session reserved its attempt; bridge to it for the terminal
            // outcome rather than re-sending chunks.
            if let Some(attempt_id) = &status.attempt_id {
                return poll_attempt(config, &status.session_id, attempt_id).map(Some);
            }
            Ok(None)
        }
        // "open" (or anything else) means chunks still need to flow.
        _ => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Source reading + streaming hash
// ---------------------------------------------------------------------------

/// The size of a source in bytes.
fn source_len(source: &ResumableSource) -> Result<u64, ResumableUploadError> {
    match source {
        ResumableSource::Bytes(b) => Ok(b.len() as u64),
        ResumableSource::Path(path) => std::fs::metadata(path)
            .map(|m| m.len())
            .map_err(|e| ResumableUploadError::Source(format!("{}: {e}", path.display()))),
    }
}

/// Read an entire source into memory (the single-shot path).
fn read_source(source: &ResumableSource) -> Result<Vec<u8>, ResumableUploadError> {
    match source {
        ResumableSource::Bytes(b) => Ok(b.clone()),
        ResumableSource::Path(path) => std::fs::read(path)
            .map_err(|e| ResumableUploadError::Source(format!("{}: {e}", path.display()))),
    }
}

/// The number of bytes read per pass when streaming a path source.
const STREAM_READ_BYTES: usize = 64 * 1024;

/// Compute the whole-file SHA-256 in one bounded-memory streaming pass.
fn stream_sha256(source: &ResumableSource) -> Result<[u8; 32], ResumableUploadError> {
    match source {
        ResumableSource::Bytes(b) => Ok(sha256_bytes(b)),
        ResumableSource::Path(path) => {
            use std::io::Read;
            let file = std::fs::File::open(path)
                .map_err(|e| ResumableUploadError::Source(format!("{}: {e}", path.display())))?;
            let mut reader = std::io::BufReader::new(file);
            let mut hasher = Sha256::new();
            let mut buf = vec![0u8; STREAM_READ_BYTES];
            loop {
                let n = reader.read(&mut buf).map_err(|e| {
                    ResumableUploadError::Source(format!("{}: {e}", path.display()))
                })?;
                if n == 0 {
                    break;
                }
                Digest::update(&mut hasher, &buf[..n]);
            }
            Ok(hasher.finalize().into())
        }
    }
}

/// Read one chunk by index from the source, honouring the server's authoritative
/// chunk size AND the declared whole-file total.
///
/// Every read is bounded to `min(chunk_bytes, total_bytes - offset)`, so the
/// final chunk is exactly the declared remainder. Bounding by `total_bytes` (not
/// just `chunk_bytes`) is what keeps the index ↔ offset grid honest when the
/// underlying file grew after the create-time hash: a path read that trusted only
/// `chunk_bytes` would pull `chunk_bytes` worth into the last chunk from the now-
/// larger file, contradicting the declared digest. The remainder bound makes the
/// last chunk a pure function of the declaration regardless of the live file size.
fn read_chunk(
    source: &ResumableSource,
    index: u32,
    chunk_bytes: u64,
    total_bytes: u64,
) -> Result<Vec<u8>, ResumableUploadError> {
    let offset = u64::from(index) * chunk_bytes;
    if offset >= total_bytes {
        return Ok(Vec::new());
    }
    // The exact number of bytes this chunk must carry per the declaration.
    let want = total_bytes.saturating_sub(offset).min(chunk_bytes);
    let want_usize = usize::try_from(want).unwrap_or(usize::MAX);
    match source {
        ResumableSource::Bytes(b) => {
            let source_len = b.len() as u64;
            // A resume whose in-memory source is shorter than the server-declared
            // grid would put `offset` at or past the buffer end; slicing
            // `b[offset..]` there panics. Reject it as a recoverable error so a
            // library/CLI never aborts on a too-short source.
            if offset >= source_len {
                return Err(ResumableUploadError::SourceTruncated {
                    index,
                    offset,
                    source_len,
                });
            }
            let end = offset.saturating_add(want);
            // The declared remainder must fit inside the actual source. A source
            // truncated below the declared total cannot produce the declared
            // chunk bytes, so surface that rather than silently sending a short
            // chunk the server's digest check would reject.
            if end > source_len {
                return Err(ResumableUploadError::SourceTruncated {
                    index,
                    offset,
                    source_len,
                });
            }
            Ok(b[offset as usize..end as usize].to_vec())
        }
        ResumableSource::Path(path) => {
            use std::io::{Read, Seek, SeekFrom};
            // Bound the path source against the declared grid the same way: a file
            // that shrank below the declared total cannot satisfy this chunk, so
            // reject it rather than seeking past EOF and returning a short read
            // the server would reject on its digest check.
            let source_len = std::fs::metadata(path)
                .map(|m| m.len())
                .map_err(|e| ResumableUploadError::Source(format!("{}: {e}", path.display())))?;
            if offset >= source_len || offset.saturating_add(want) > source_len {
                return Err(ResumableUploadError::SourceTruncated {
                    index,
                    offset,
                    source_len,
                });
            }
            let mut file = std::fs::File::open(path)
                .map_err(|e| ResumableUploadError::Source(format!("{}: {e}", path.display())))?;
            file.seek(SeekFrom::Start(offset))
                .map_err(|e| ResumableUploadError::Source(format!("{}: {e}", path.display())))?;
            let mut buf = vec![0u8; want_usize];
            let mut filled = 0usize;
            // A single read may return fewer bytes than requested; loop to fill
            // the chunk to its declared length (or stop at EOF for a short read).
            // The buffer is sized to the declared remainder, so a file that grew
            // since the hash can never push extra bytes past `want`.
            loop {
                let n = file.read(&mut buf[filled..]).map_err(|e| {
                    ResumableUploadError::Source(format!("{}: {e}", path.display()))
                })?;
                if n == 0 {
                    break;
                }
                filled += n;
                if filled == buf.len() {
                    break;
                }
            }
            // A file that shrank between the metadata check above and this read
            // stops the loop early at EOF with fewer than the declared bytes.
            // Reject it as a recoverable error rather than returning a short chunk
            // the server would reject on its digest check, keeping parity with the
            // in-memory bounds checks above.
            if filled != want_usize {
                return Err(ResumableUploadError::SourceTruncated {
                    index,
                    offset,
                    source_len: offset.saturating_add(filled as u64),
                });
            }
            Ok(buf)
        }
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// SHA-256 of a byte slice.
fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The default completion idempotency key, derived deterministically from the
/// declared whole-file digest (lowercase hex).
///
/// The `resumable-<sha256hex>` shape is shared with the other-language SDKs so a
/// TypeScript client and a Rust client completing the same content compute an
/// identical key; the gateway then replays one recorded terminal result for both.
fn default_idempotency_key(declared_sha256_hex: &str) -> String {
    format!("resumable-{declared_sha256_hex}")
}

/// Standard base64 (RFC 4648, with padding) of a byte slice.
///
/// Hand-rolled rather than pulling a base64 crate into the feature graph: the
/// only base64 the SDK emits is the per-chunk `Digest` header, and a self-
/// contained encoder keeps the transport-free build dependency-clean.
fn base64_standard(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for triple in bytes.chunks(3) {
        let b0 = triple[0] as u32;
        let b1 = *triple.get(1).unwrap_or(&0) as u32;
        let b2 = *triple.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        if triple.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if triple.len() > 2 {
            out.push(ALPHABET[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Parse a JSON body into `T`, mapping a decode failure to the resumable error.
fn parse<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, ResumableUploadError> {
    serde_json::from_slice(body).map_err(|e| ResumableUploadError::Decode(e.to_string()))
}

/// Lift a funding `402` into the typed variant, carrying the verbatim problem.
fn funding_error(response: crate::client::transport::ClientResponse) -> ResumableUploadError {
    match into_http_error(response) {
        Err(ClientError::Http(boxed)) => ResumableUploadError::InsufficientFunds(boxed),
        Err(other) => ResumableUploadError::Http(other),
        // A 402 always maps to an Http error; this arm is unreachable in
        // practice but keeps the function total.
        Ok(_) => ResumableUploadError::Protocol("a 402 response parsed as success".into()),
    }
}

/// Whether a chunk-PUT HTTP error is the client's fault (terminal) rather than a
/// transient server/transport hiccup worth retrying.
fn is_terminal_chunk_error(err: &ResumableUploadError) -> bool {
    match err {
        ResumableUploadError::Http(ClientError::Http(boxed)) => {
            let status = boxed.http_status();
            // Any definitive client-side 4xx is terminal: a conflicting digest,
            // a size mismatch, an unauthorised/forbidden caller, an expired or
            // missing session. 408 (request timeout) and 429 (rate limited) are
            // worth a retry.
            (400..500).contains(&status) && status != 408 && status != 429
        }
        // A transport/egress failure is transient.
        ResumableUploadError::Http(_) => false,
        // Anything else surfaced here is already terminal.
        _ => true,
    }
}

/// Percent-encode a path segment for the characters that occur in a session id /
/// attempt id (UUIDs are unreserved, but a defensive encoder keeps a non-UUID
/// caller safe).
fn encode_path_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        let unreserved = byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
            );
        if unreserved {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_standard_matches_known_vectors() {
        // RFC 4648 test vectors.
        assert_eq!(base64_standard(b""), "");
        assert_eq!(base64_standard(b"f"), "Zg==");
        assert_eq!(base64_standard(b"fo"), "Zm8=");
        assert_eq!(base64_standard(b"foo"), "Zm9v");
        assert_eq!(base64_standard(b"foob"), "Zm9vYg==");
        assert_eq!(base64_standard(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_standard(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64_standard_round_trips_a_sha256_digest() {
        let digest = sha256_bytes(b"the quick brown fox");
        let b64 = base64_standard(&digest);
        // 32 bytes -> 44 base64 characters (with one '=' pad).
        assert_eq!(b64.len(), 44);
        assert!(b64.ends_with('='));
    }

    #[test]
    fn read_chunk_slices_in_memory_bytes_with_a_short_final_chunk() {
        let data: Vec<u8> = (0u8..=255).collect();
        let total = data.len() as u64;
        let source = ResumableSource::Bytes(data.clone());
        let chunk_bytes = 100u64;
        let c0 = read_chunk(&source, 0, chunk_bytes, total).unwrap();
        let c1 = read_chunk(&source, 1, chunk_bytes, total).unwrap();
        let c2 = read_chunk(&source, 2, chunk_bytes, total).unwrap();
        assert_eq!(c0, &data[0..100]);
        assert_eq!(c1, &data[100..200]);
        assert_eq!(c2, &data[200..256]);
        assert_eq!(c2.len(), 56, "the final chunk is the remainder");
        // Reassembly equals the original.
        let mut joined = c0;
        joined.extend(c1);
        joined.extend(c2);
        assert_eq!(joined, data);
    }

    #[test]
    fn read_chunk_bounds_the_final_chunk_to_the_declared_total_when_the_file_grew() {
        // The declared total is 250 bytes (the size hashed at create time). The
        // file on disk has since grown to 300 bytes. With a 100-byte chunk size,
        // the final chunk (index 2) must be exactly the declared remainder (50
        // bytes), NOT a full 100-byte read from the now-larger file. Bounding the
        // read by total_bytes is what keeps the chunk grid consistent with the
        // declared digest.
        let declared_total = 250u64;
        let chunk_bytes = 100u64;
        let grown: Vec<u8> = (0u8..=255).chain(0u8..44).collect(); // 300 bytes
        assert_eq!(grown.len(), 300);

        let dir = std::env::temp_dir();
        let path = dir.join(format!("cw-resumable-grown-{}.bin", std::process::id()));
        std::fs::write(&path, &grown).unwrap();
        let source = ResumableSource::Path(path.clone());

        let last = read_chunk(&source, 2, chunk_bytes, declared_total).unwrap();
        let _ = std::fs::remove_file(&path);

        // The last chunk is exactly the declared remainder: 250 - 200 = 50 bytes,
        // and those bytes are the original declared tail, not the grown extension.
        assert_eq!(last.len(), 50, "final chunk is the declared remainder");
        assert_eq!(last, &grown[200..250]);
    }

    #[test]
    fn read_chunk_bytes_source_bounds_final_chunk_to_declared_total() {
        // The in-memory blob is longer than the declared total (e.g. the caller
        // passed a buffer that was re-grown after the create-time hash). The final
        // chunk must still be the declared remainder, never a full chunk read.
        let declared_total = 150u64;
        let chunk_bytes = 100u64;
        let oversized: Vec<u8> = (0u8..200).collect();
        let source = ResumableSource::Bytes(oversized.clone());
        let last = read_chunk(&source, 1, chunk_bytes, declared_total).unwrap();
        assert_eq!(last.len(), 50, "final chunk honours the declared total");
        assert_eq!(last, &oversized[100..150]);
    }

    #[test]
    fn stream_sha256_equals_one_shot_for_in_memory_bytes() {
        let data = b"resumable-upload-content".to_vec();
        let streamed = stream_sha256(&ResumableSource::Bytes(data.clone())).unwrap();
        assert_eq!(streamed, sha256_bytes(&data));
    }

    #[test]
    fn read_chunk_too_short_in_memory_resume_source_returns_a_recoverable_error() {
        // A resume whose declared grid (total 250, 100-byte chunks => index 2 at
        // offset 200) is served by an in-memory source that is now only 50 bytes:
        // the offset is past the buffer. The old code sliced `b[200..]` and
        // PANICKED. The guard must turn this into a recoverable SourceTruncated
        // error instead, so a library/CLI never aborts on a too-short source.
        let declared_total = 250u64;
        let chunk_bytes = 100u64;
        let too_short: Vec<u8> = (0u8..50).collect();
        let source = ResumableSource::Bytes(too_short);

        let err = read_chunk(&source, 2, chunk_bytes, declared_total).unwrap_err();
        match err {
            ResumableUploadError::SourceTruncated {
                index,
                offset,
                source_len,
            } => {
                assert_eq!(index, 2);
                assert_eq!(offset, 200);
                assert_eq!(source_len, 50);
            }
            other => panic!("expected SourceTruncated, got {other:?}"),
        }
    }

    #[test]
    fn read_chunk_partially_short_in_memory_source_returns_a_recoverable_error() {
        // The offset is inside the buffer but the declared remainder runs past its
        // end (offset 100, want 50, but only 120 bytes available). Sending a short
        // chunk would fail the server's digest check, so this is rejected as a
        // recoverable SourceTruncated rather than silently producing a 20-byte chunk.
        let declared_total = 150u64;
        let chunk_bytes = 100u64;
        let partial: Vec<u8> = (0u8..120).collect();
        let source = ResumableSource::Bytes(partial);

        let err = read_chunk(&source, 1, chunk_bytes, declared_total).unwrap_err();
        assert!(
            matches!(err, ResumableUploadError::SourceTruncated { index: 1, .. }),
            "expected SourceTruncated for a partially short source, got {err:?}"
        );
    }

    #[test]
    fn read_chunk_too_short_path_resume_source_returns_a_recoverable_error() {
        // The same guard applies to a path source that shrank below the declared
        // grid: rather than seeking past EOF and returning a short read, the helper
        // surfaces a recoverable SourceTruncated error.
        let declared_total = 250u64;
        let chunk_bytes = 100u64;
        let too_short: Vec<u8> = (0u8..50).collect();

        let dir = std::env::temp_dir();
        let path = dir.join(format!("cw-resumable-short-{}.bin", std::process::id()));
        std::fs::write(&path, &too_short).unwrap();
        let source = ResumableSource::Path(path.clone());

        let result = read_chunk(&source, 2, chunk_bytes, declared_total);
        let _ = std::fs::remove_file(&path);

        let err = result.unwrap_err();
        assert!(
            matches!(err, ResumableUploadError::SourceTruncated { index: 2, .. }),
            "expected SourceTruncated for a too-short path source, got {err:?}"
        );
    }

    #[test]
    fn default_idempotency_key_matches_the_cross_sdk_scheme() {
        // The format string MUST be `resumable-<sha256hex>` so a TypeScript client
        // and a Rust client computing the key for the same content agree.
        let hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef0";
        assert_eq!(
            default_idempotency_key(hex),
            format!("resumable-{hex}"),
            "default key must be resumable-<declared sha256 hex>"
        );
    }
}
