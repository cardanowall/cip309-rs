// Resumable / chunked upload helper coverage. Assertions target the protocol the
// helper drives — the path-selection gate, the multi-chunk session flow, the
// resume-from-missing contract, the create-time dedup short-circuit, the
// accepted -> poll convergence, and the funding short-circuit — never log
// strings. Every case runs through the capturing MockTransport, so the exact
// request sequence (method, URL, headers, body) is observable.

use cardanowall::client::DEFAULT_RESUMABLE_THRESHOLD_BYTES;

/// Standard base64 (RFC 4648, padded) — independent of the SDK's encoder so the
/// Digest-header assertion is a genuine cross-check, not a tautology.
fn b64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(A[((n >> 18) & 63) as usize] as char);
        out.push(A[((n >> 12) & 63) as usize] as char);
        out.push(if c.len() > 1 {
            A[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            A[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    cardanowall::hex::encode(&cardanowall::hash::sha256(bytes))
}

fn resumable_input(source: Vec<u8>) -> ResumableUploadInput {
    ResumableUploadInput {
        target: "arweave".to_string(),
        source: ResumableSource::Bytes(source),
        content_type: None,
        threshold_bytes: None,
        chunk_bytes: None,
        resume_session_id: None,
        idempotency_key: None,
    }
}

// ---------------------------------------------------------------------------
// Threshold gate
// ---------------------------------------------------------------------------

#[test]
fn small_source_takes_the_single_shot_path() {
    // A source at/under the threshold rides the existing single-shot multipart
    // POST /uploads — one request, no session sub-resource is ever touched.
    let content = b"a small blob".to_vec();
    let upload_body = serde_json::json!({
        "uploads": [{
            "idx": 0, "ok": true,
            "uri": "ar://single-shot-tx",
            "sha256": sha256_hex(&content),
            "bytes": content.len(),
        }]
    });
    let transport = Box::new(MockTransport::single(StubResponse::json(200, upload_body)));
    let (client, ptr) = client_with("https://gw.example.com", Some(&bearer_key()), transport);

    let mut input = resumable_input(content.clone());
    input.threshold_bytes = Some(content.len() as u64); // <= threshold -> single-shot
    let result = client.poe().upload_resumable(&input).unwrap();

    assert_eq!(result.uri, "ar://single-shot-tx");
    assert!(result.session_id.is_none(), "single-shot uses no session");
    assert!(!result.deduplicated);
    assert_eq!(mock(ptr).call_count(), 1, "exactly one request");
    let req = mock(ptr).first();
    assert_eq!(req.method, HttpMethod::Post);
    assert!(req.url.ends_with("/api/v1/poe/uploads"));
    // It is a multipart body, not a session JSON create.
    matches!(req.body, RequestBodySnapshot::Multipart(_));
}

// ---------------------------------------------------------------------------
// Multi-chunk assemble
// ---------------------------------------------------------------------------

#[test]
fn large_source_runs_the_session_flow_and_assembles_in_chunks() {
    // A 250-byte source over a forced 5-byte threshold + 100-byte chunk size:
    // create -> 3 chunk PUTs (100, 100, 50) -> complete. The declared hash, the
    // chunk slices, the per-chunk Digest headers, and the terminal URI are all
    // asserted on the wire.
    let content: Vec<u8> = (0u8..250).collect();
    let whole_hex = sha256_hex(&content);

    let create = StubResponse::json(
        201,
        serde_json::json!({
            "session_id": "01956b41-7c00-7000-8000-0000000000aa",
            "chunk_bytes": 100,
            "chunk_count": 3,
            "received": [],
            "expires_at": "2026-06-09T00:00:00Z",
            "max_chunk_bytes": 67108864,
        }),
    );
    let chunk_ack = |idx: u32, received: Vec<u32>, complete: bool| {
        let remaining = 3u32 - received.len() as u32;
        StubResponse::json(
            200,
            serde_json::json!({
                "index": idx,
                "received": received,
                "remaining": remaining,
                "complete": complete,
            }),
        )
    };
    let complete = StubResponse::json(
        200,
        serde_json::json!({
            "ok": true,
            "uri": "ar://assembled-tx",
            "sha256": whole_hex,
            "bytes": 250,
            "charged_usd_micros": 4242,
        }),
    );

    let transport = Box::new(MockTransport::new(vec![
        create,
        chunk_ack(0, vec![0], false),
        chunk_ack(1, vec![0, 1], false),
        chunk_ack(2, vec![0, 1, 2], true),
        complete,
    ]));
    let (client, ptr) = client_with("https://gw.example.com", Some(&bearer_key()), transport);

    let mut input = resumable_input(content.clone());
    input.threshold_bytes = Some(5);
    input.chunk_bytes = Some(100);
    let result = client.poe().upload_resumable(&input).unwrap();

    // Terminal outcome.
    assert_eq!(result.uri, "ar://assembled-tx");
    assert_eq!(result.charged_usd_micros, Some(4242));
    assert!(!result.deduplicated);
    assert_eq!(
        result.session_id.as_deref(),
        Some("01956b41-7c00-7000-8000-0000000000aa")
    );

    // Request sequence: create + 3 chunks + complete.
    assert_eq!(mock(ptr).call_count(), 5);

    // Create declares the whole-file hash + size + the requested chunk size.
    let create_req = mock(ptr).nth(0);
    assert_eq!(create_req.method, HttpMethod::Post);
    assert!(create_req.url.ends_with("/api/v1/poe/uploads/sessions"));
    let create_json: serde_json::Value =
        serde_json::from_str(create_req.body.as_json()).unwrap();
    assert_eq!(create_json["sha256"], whole_hex);
    assert_eq!(create_json["total_bytes"], 250);
    assert_eq!(create_json["chunk_bytes"], 100);
    assert_eq!(create_json["target"], "arweave");

    // Each chunk PUT carries its slice, a matching Digest, and the correct index.
    for (idx, range) in [(0u32, 0..100usize), (1, 100..200), (2, 200..250)] {
        let req = mock(ptr).nth(1 + idx as usize);
        assert_eq!(req.method, HttpMethod::Put);
        assert!(req
            .url
            .ends_with(&format!("/api/v1/poe/uploads/sessions/01956b41-7c00-7000-8000-0000000000aa/chunks/{idx}")));
        let slice = &content[range];
        assert_eq!(req.body.as_bytes(), slice, "chunk {idx} bytes");
        // The required RFC 9530 Digest header is sha-256=<base64(sha256(slice))>.
        let expected_digest = format!("sha-256={}", b64(&cardanowall::hash::sha256(slice)));
        assert_eq!(header(&req, "digest").as_deref(), Some(expected_digest.as_str()));
        assert_eq!(
            header(&req, "content-length").as_deref(),
            Some(slice.len().to_string().as_str())
        );
    }

    // Complete is a POST to the session's /complete with the bearer.
    let complete_req = mock(ptr).nth(4);
    assert_eq!(complete_req.method, HttpMethod::Post);
    assert!(complete_req.url.ends_with("/complete"));
    assert_eq!(
        header(&complete_req, "authorization").as_deref(),
        Some(format!("Bearer {}", bearer_key()).as_str())
    );
}

// ---------------------------------------------------------------------------
// Resume: GET status -> send only the missing indices -> complete
// ---------------------------------------------------------------------------

#[test]
fn resume_sends_only_the_missing_chunks() {
    // A reconnecting client passes the original session id. The helper GETs the
    // session, reads `missing == [1]`, sends ONLY chunk 1, and completes. Chunks
    // 0 and 2 are never re-sent.
    let content: Vec<u8> = (0u8..250).collect();
    let whole_hex = sha256_hex(&content);

    let status = StubResponse::json(
        200,
        serde_json::json!({
            "session_id": "01956b41-7c00-7000-8000-0000000000bb",
            "state": "open",
            "sha256": whole_hex,
            "total_bytes": 250,
            "chunk_bytes": 100,
            "chunk_count": 3,
            "received": [0, 2],
            "missing": [1],
            "expires_at": "2026-06-09T00:00:00Z",
            "attempt_id": null,
            "uri": null,
        }),
    );
    let chunk_ack = StubResponse::json(
        200,
        serde_json::json!({ "index": 1, "received": [0,1,2], "remaining": 0, "complete": true }),
    );
    let complete = StubResponse::json(
        200,
        serde_json::json!({ "ok": true, "uri": "ar://resumed-tx", "sha256": whole_hex, "bytes": 250, "charged_usd_micros": 7 }),
    );

    let transport = Box::new(MockTransport::new(vec![status, chunk_ack, complete]));
    let (client, ptr) = client_with("https://gw.example.com", Some(&bearer_key()), transport);

    let mut input = resumable_input(content.clone());
    input.chunk_bytes = Some(100);
    input.resume_session_id = Some("01956b41-7c00-7000-8000-0000000000bb".to_string());
    let result = client.poe().upload_resumable(&input).unwrap();

    assert_eq!(result.uri, "ar://resumed-tx");
    assert_eq!(mock(ptr).call_count(), 3, "status + one chunk + complete");

    // First call is a GET status, not a create.
    let status_req = mock(ptr).nth(0);
    assert_eq!(status_req.method, HttpMethod::Get);
    assert!(status_req
        .url
        .ends_with("/api/v1/poe/uploads/sessions/01956b41-7c00-7000-8000-0000000000bb"));

    // The single chunk PUT is index 1 with the right slice — chunks 0 and 2 are
    // never sent.
    let put_req = mock(ptr).nth(1);
    assert_eq!(put_req.method, HttpMethod::Put);
    assert!(put_req.url.ends_with("/chunks/1"));
    assert_eq!(put_req.body.as_bytes(), &content[100..200]);

    let complete_req = mock(ptr).nth(2);
    assert!(complete_req.url.ends_with("/complete"));
}

// ---------------------------------------------------------------------------
// Dedup short-circuit at create
// ---------------------------------------------------------------------------

#[test]
fn create_dedup_short_circuit_uploads_no_bytes() {
    // The declared bytes are already a committed receipt: create returns 200
    // { deduplicated: true, uri }. The helper returns that URI and sends NO
    // chunks and NO complete.
    let content: Vec<u8> = (0u8..200).collect();
    let dedup = StubResponse::json(
        200,
        serde_json::json!({
            "deduplicated": true,
            "uri": "ar://already-stored",
            "sha256": sha256_hex(&content),
            "bytes": content.len(),
            "charged_usd_micros": 0,
        }),
    );
    let transport = Box::new(MockTransport::single(dedup));
    let (client, ptr) = client_with("https://gw.example.com", Some(&bearer_key()), transport);

    let mut input = resumable_input(content);
    input.threshold_bytes = Some(5);
    input.chunk_bytes = Some(100);
    let result = client.poe().upload_resumable(&input).unwrap();

    assert_eq!(result.uri, "ar://already-stored");
    assert!(result.deduplicated);
    assert_eq!(result.charged_usd_micros, Some(0));
    assert!(result.session_id.is_none(), "a dedup hit creates no session");
    assert_eq!(mock(ptr).call_count(), 1, "only the create call");
}

// ---------------------------------------------------------------------------
// accepted -> poll the attempt endpoint to the terminal outcome
// ---------------------------------------------------------------------------

#[test]
fn complete_accepted_then_polls_attempt_to_committed() {
    // complete returns { accepted, attempt_id }; the helper polls
    // GET /uploads/attempts/{id} until it is committed, then returns the URI.
    let content: Vec<u8> = (0u8..150).collect();
    let whole_hex = sha256_hex(&content);

    let create = StubResponse::json(
        201,
        serde_json::json!({
            "session_id": "01956b41-7c00-7000-8000-0000000000cc",
            "chunk_bytes": 100,
            "chunk_count": 2,
            "received": [],
            "expires_at": "2026-06-09T00:00:00Z",
            "max_chunk_bytes": 67108864,
        }),
    );
    let ack0 = StubResponse::json(
        200,
        serde_json::json!({ "index": 0, "received": [0], "remaining": 1, "complete": false }),
    );
    let ack1 = StubResponse::json(
        200,
        serde_json::json!({ "index": 1, "received": [0,1], "remaining": 0, "complete": true }),
    );
    let accepted = StubResponse::json(
        200,
        serde_json::json!({ "accepted": true, "attempt_id": "01956b41-7c00-7000-8000-0000000000dd" }),
    );
    let reserved = StubResponse::json(
        200,
        serde_json::json!({
            "attempt_id": "01956b41-7c00-7000-8000-0000000000dd",
            "state": "reserved",
            "sha256": whole_hex,
            "bytes": 150,
            "backend": "turbo",
        }),
    );
    let committed = StubResponse::json(
        200,
        serde_json::json!({
            "attempt_id": "01956b41-7c00-7000-8000-0000000000dd",
            "state": "committed",
            "sha256": whole_hex,
            "bytes": 150,
            "backend": "turbo",
            "uri": "ar://polled-tx",
            "charged_usd_micros": 99,
        }),
    );

    let transport = Box::new(MockTransport::new(vec![
        create, ack0, ack1, accepted, reserved, committed,
    ]));
    let (client, ptr) = client_with("https://gw.example.com", Some(&bearer_key()), transport);

    let mut input = resumable_input(content);
    input.threshold_bytes = Some(5);
    input.chunk_bytes = Some(100);
    let result = client.poe().upload_resumable(&input).unwrap();

    assert_eq!(result.uri, "ar://polled-tx");
    assert_eq!(result.charged_usd_micros, Some(99));
    // create + 2 chunks + complete + 2 attempt polls (reserved then committed).
    assert_eq!(mock(ptr).call_count(), 6);
    let first_poll = mock(ptr).nth(4);
    assert_eq!(first_poll.method, HttpMethod::Get);
    assert!(first_poll
        .url
        .ends_with("/api/v1/poe/uploads/attempts/01956b41-7c00-7000-8000-0000000000dd"));
}

// ---------------------------------------------------------------------------
// Funding rejection at create
// ---------------------------------------------------------------------------

#[test]
fn create_funding_rejection_surfaces_typed_error() {
    // A 402 at create (chargeable bytes the account cannot fund) surfaces as the
    // typed InsufficientFunds error carrying the verbatim problem; no chunk flows.
    let content: Vec<u8> = (0u8..200).collect();
    let problem = problem_body(serde_json::json!({
        "status": 402,
        "code": "insufficient-funds",
        "title": "Insufficient funds",
        "detail": "the account balance is below the upload cost",
        "balance_usd_micros": 1000,
        "required_usd_micros": 500000,
    }));
    let transport = Box::new(MockTransport::single(StubResponse::json(402, problem)));
    let (client, ptr) = client_with("https://gw.example.com", Some(&bearer_key()), transport);

    let mut input = resumable_input(content);
    input.threshold_bytes = Some(5);
    input.chunk_bytes = Some(100);
    let err = client.poe().upload_resumable(&input).unwrap_err();

    match err {
        ResumableUploadError::InsufficientFunds(problem) => {
            assert_eq!(problem.http_status(), 402);
            assert_eq!(problem.code(), "insufficient-funds");
            assert!(matches!(
                problem.kind(),
                HttpErrorKind::InsufficientFunds { .. }
            ));
        }
        other => panic!("expected InsufficientFunds, got {other:?}"),
    }
    assert_eq!(mock(ptr).call_count(), 1, "rejected before any chunk");
}

// ---------------------------------------------------------------------------
// Server max_chunk_bytes is authoritative
// ---------------------------------------------------------------------------

#[test]
fn server_chunk_bytes_overrides_the_client_request() {
    // The client requests 100-byte chunks, but the server clamps to 60 and
    // reports chunk_bytes=60 / chunk_count=4 in the create response. The helper
    // honours the server value: it slices at 60 bytes, not the requested 100.
    let content: Vec<u8> = (0u8..200).collect();
    let whole_hex = sha256_hex(&content);

    let create = StubResponse::json(
        201,
        serde_json::json!({
            "session_id": "01956b41-7c00-7000-8000-0000000000ee",
            "chunk_bytes": 60,          // server clamped down from the requested 100
            "chunk_count": 4,           // ceil(200 / 60)
            "received": [],
            "expires_at": "2026-06-09T00:00:00Z",
            "max_chunk_bytes": 60,
        }),
    );
    let ack = |idx: u32, complete: bool| {
        StubResponse::json(
            200,
            serde_json::json!({ "index": idx, "received": [idx], "remaining": 0, "complete": complete }),
        )
    };
    let complete = StubResponse::json(
        200,
        serde_json::json!({ "ok": true, "uri": "ar://clamped-tx", "sha256": whole_hex, "bytes": 200, "charged_usd_micros": 1 }),
    );

    let transport = Box::new(MockTransport::new(vec![
        create,
        ack(0, false),
        ack(1, false),
        ack(2, false),
        ack(3, true),
        complete,
    ]));
    let (client, ptr) = client_with("https://gw.example.com", Some(&bearer_key()), transport);

    let mut input = resumable_input(content.clone());
    input.threshold_bytes = Some(5);
    input.chunk_bytes = Some(100); // requested 100, but the server says 60
    let result = client.poe().upload_resumable(&input).unwrap();
    assert_eq!(result.uri, "ar://clamped-tx");

    // Four chunks at the SERVER's 60-byte boundary: 60, 60, 60, 20.
    for (idx, range) in [(0u32, 0..60usize), (1, 60..120), (2, 120..180), (3, 180..200)] {
        let req = mock(ptr).nth(1 + idx as usize);
        assert_eq!(req.method, HttpMethod::Put);
        assert!(req.url.ends_with(&format!("/chunks/{idx}")));
        assert_eq!(req.body.as_bytes(), &content[range], "chunk {idx} honours server chunk_bytes");
    }
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

#[test]
fn default_threshold_drives_path_selection_below_the_cdn_cap() {
    // With no explicit threshold, a source one byte over the default takes the
    // chunked path (it would create a session); a source at the default takes the
    // single-shot path. Asserting the BEHAVIOUR at the boundary, not the literal:
    // a regressed default that crossed the ~100 MB CDN cap would route a too-large
    // body single-shot and 413 at the proxy — this guards the boundary.
    let create = StubResponse::json(
        201,
        serde_json::json!({
            "session_id": "01956b41-7c00-7000-8000-0000000000ff",
            "chunk_bytes": DEFAULT_RESUMABLE_THRESHOLD_BYTES,
            "chunk_count": 0,
            "received": [],
            "expires_at": "2026-06-09T00:00:00Z",
            "max_chunk_bytes": DEFAULT_RESUMABLE_THRESHOLD_BYTES,
        }),
    );
    // A small source on a default threshold goes single-shot — one multipart call.
    let single = StubResponse::json(
        200,
        serde_json::json!({
            "uploads": [{ "idx": 0, "ok": true, "uri": "ar://x", "sha256": sha256_hex(b"hi"), "bytes": 2 }]
        }),
    );
    let transport = Box::new(MockTransport::new(vec![single, create]));
    let (client, ptr) = client_with("https://gw.example.com", Some(&bearer_key()), transport);

    // Default threshold (~48 MiB): a 2-byte source is well below it -> single-shot.
    let input = resumable_input(b"hi".to_vec());
    let result = client.poe().upload_resumable(&input).unwrap();
    assert_eq!(result.uri, "ar://x");
    assert!(result.session_id.is_none());
    assert_eq!(mock(ptr).call_count(), 1);
    assert!(mock(ptr).first().url.ends_with("/api/v1/poe/uploads"));

    // The default is the owner-mandated 48 MiB, comfortably under the ~100 MB cap.
    assert_eq!(DEFAULT_RESUMABLE_THRESHOLD_BYTES, 50_331_648);
}

// ---------------------------------------------------------------------------
// 409 incomplete-upload at complete -> resume the gap -> retry complete
// ---------------------------------------------------------------------------

#[test]
fn complete_409_incomplete_resumes_the_missing_chunk_then_succeeds() {
    // The first /complete returns 409 incomplete-upload with missing: [1] (a chunk
    // acknowledged client-side that did not persist). The helper re-reads the
    // session status, re-sends ONLY chunk 1, and retries complete, which then
    // succeeds. The retry is the protocol's intended resume, not a raw error.
    let content: Vec<u8> = (0u8..250).collect();
    let whole_hex = sha256_hex(&content);

    let create = StubResponse::json(
        201,
        serde_json::json!({
            "session_id": "01956b41-7c00-7000-8000-000000000111",
            "chunk_bytes": 100,
            "chunk_count": 3,
            "received": [],
            "expires_at": "2026-06-09T00:00:00Z",
            "max_chunk_bytes": 67108864,
        }),
    );
    let chunk_ack = |idx: u32, received: Vec<u32>, complete: bool| {
        let remaining = 3u32 - received.len() as u32;
        StubResponse::json(
            200,
            serde_json::json!({
                "index": idx, "received": received, "remaining": remaining, "complete": complete,
            }),
        )
    };
    // First complete: 409 incomplete-upload carrying the missing set.
    let complete_409 = StubResponse::json(
        409,
        problem_body(serde_json::json!({
            "status": 409,
            "code": "incomplete-upload",
            "title": "Conflict",
            "detail": "not every chunk has been received",
            "missing": [1],
        })),
    );
    // The resume status GET reports chunk 1 still missing.
    let status_missing_1 = StubResponse::json(
        200,
        serde_json::json!({
            "session_id": "01956b41-7c00-7000-8000-000000000111",
            "state": "open",
            "sha256": whole_hex,
            "total_bytes": 250,
            "chunk_bytes": 100,
            "chunk_count": 3,
            "received": [0, 2],
            "missing": [1],
            "expires_at": "2026-06-09T00:00:00Z",
            "attempt_id": null,
            "uri": null,
        }),
    );
    let resend_ack = StubResponse::json(
        200,
        serde_json::json!({ "index": 1, "received": [0,1,2], "remaining": 0, "complete": true }),
    );
    let complete_ok = StubResponse::json(
        200,
        serde_json::json!({
            "ok": true, "uri": "ar://resumed-after-409", "sha256": whole_hex, "bytes": 250, "charged_usd_micros": 11,
        }),
    );

    let transport = Box::new(MockTransport::new(vec![
        create,
        chunk_ack(0, vec![0], false),
        chunk_ack(1, vec![0, 1], false),
        chunk_ack(2, vec![0, 1, 2], true),
        complete_409,
        status_missing_1,
        resend_ack,
        complete_ok,
    ]));
    let (client, ptr) = client_with("https://gw.example.com", Some(&bearer_key()), transport);

    let mut input = resumable_input(content.clone());
    input.threshold_bytes = Some(5);
    input.chunk_bytes = Some(100);
    let result = client.poe().upload_resumable(&input).unwrap();

    // The resume converged on the terminal URI.
    assert_eq!(result.uri, "ar://resumed-after-409");
    assert_eq!(result.charged_usd_micros, Some(11));

    // create + 3 chunks + complete(409) + status + resend chunk 1 + complete(200).
    assert_eq!(mock(ptr).call_count(), 8);

    // The first complete was a POST to /complete.
    let first_complete = mock(ptr).nth(4);
    assert_eq!(first_complete.method, HttpMethod::Post);
    assert!(first_complete.url.ends_with("/complete"));

    // The resume re-read status (GET), not a re-create.
    let status_req = mock(ptr).nth(5);
    assert_eq!(status_req.method, HttpMethod::Get);
    assert!(status_req
        .url
        .ends_with("/api/v1/poe/uploads/sessions/01956b41-7c00-7000-8000-000000000111"));

    // Exactly chunk 1 was re-sent, with the right slice — chunks 0 and 2 are not.
    let resend_req = mock(ptr).nth(6);
    assert_eq!(resend_req.method, HttpMethod::Put);
    assert!(resend_req.url.ends_with("/chunks/1"));
    assert_eq!(resend_req.body.as_bytes(), &content[100..200]);

    // The second complete is again a POST to /complete and is the one that won.
    let second_complete = mock(ptr).nth(7);
    assert_eq!(second_complete.method, HttpMethod::Post);
    assert!(second_complete.url.ends_with("/complete"));
}

// ---------------------------------------------------------------------------
// accepted -> poll paces between attempts and tolerates a long-reserved attempt
// ---------------------------------------------------------------------------

#[test]
fn poll_attempt_paces_between_polls_and_does_not_reject_a_long_reserved_attempt() {
    // A real Turbo/Arweave commit stays `reserved` for seconds. The poll must wait
    // between attempts and keep polling rather than spin a tight loop that rejects
    // a still-valid upload prematurely. This feeds several `reserved` polls before
    // `committed`; the helper must converge on the URI (no premature error), and
    // the paced sleep between polls must make the wall-clock elapsed measurably
    // non-zero (a tight spin would finish in microseconds).
    let content: Vec<u8> = (0u8..150).collect();
    let whole_hex = sha256_hex(&content);

    let create = StubResponse::json(
        201,
        serde_json::json!({
            "session_id": "01956b41-7c00-7000-8000-000000000222",
            "chunk_bytes": 100,
            "chunk_count": 2,
            "received": [],
            "expires_at": "2026-06-09T00:00:00Z",
            "max_chunk_bytes": 67108864,
        }),
    );
    let ack = |idx: u32, complete: bool| {
        StubResponse::json(
            200,
            serde_json::json!({ "index": idx, "received": [idx], "remaining": 0, "complete": complete }),
        )
    };
    let accepted = StubResponse::json(
        200,
        serde_json::json!({ "accepted": true, "attempt_id": "01956b41-7c00-7000-8000-000000000333" }),
    );
    let reserved = || {
        StubResponse::json(
            200,
            serde_json::json!({
                "attempt_id": "01956b41-7c00-7000-8000-000000000333",
                "state": "reserved",
                "sha256": whole_hex,
                "bytes": 150,
                "backend": "turbo",
            }),
        )
    };
    let committed = StubResponse::json(
        200,
        serde_json::json!({
            "attempt_id": "01956b41-7c00-7000-8000-000000000333",
            "state": "committed",
            "sha256": whole_hex,
            "bytes": 150,
            "backend": "turbo",
            "uri": "ar://paced-poll-tx",
            "charged_usd_micros": 5,
        }),
    );

    // Three reserved polls before the commit lands: the old tight loop would have
    // burned its whole budget in microseconds; the paced loop waits and converges.
    let transport = Box::new(MockTransport::new(vec![
        create,
        ack(0, false),
        ack(1, true),
        accepted,
        reserved(),
        reserved(),
        reserved(),
        committed,
    ]));
    let (client, ptr) = client_with("https://gw.example.com", Some(&bearer_key()), transport);

    let mut input = resumable_input(content);
    input.threshold_bytes = Some(5);
    input.chunk_bytes = Some(100);

    let started = std::time::Instant::now();
    let result = client.poe().upload_resumable(&input).unwrap();
    let elapsed = started.elapsed();

    assert_eq!(result.uri, "ar://paced-poll-tx");
    assert_eq!(result.charged_usd_micros, Some(5));
    // create + 2 chunks + complete + 4 attempt polls (3 reserved, 1 committed).
    assert_eq!(mock(ptr).call_count(), 8);
    // The helper slept between the four polls rather than spinning: three inter-poll
    // intervals at ~1s each means the run cannot have finished near-instantly.
    assert!(
        elapsed >= std::time::Duration::from_secs(2),
        "poll loop must pace between attempts, elapsed was {elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// complete derives the default idempotency key from the declared digest
// ---------------------------------------------------------------------------

#[test]
fn complete_default_idempotency_key_matches_the_resumable_sha256_scheme() {
    // When the caller supplies no idempotency key, the helper must derive the SAME
    // deterministic default the other-language SDKs use: `resumable-<sha256hex>`
    // over the declared whole-file digest. A TS and a Rust client completing the
    // same content then send an identical key and replay one terminal result.
    let content: Vec<u8> = (0u8..250).collect();
    let whole_hex = sha256_hex(&content);

    let create = StubResponse::json(
        201,
        serde_json::json!({
            "session_id": "01956b41-7c00-7000-8000-000000000444",
            "chunk_bytes": 100,
            "chunk_count": 3,
            "received": [],
            "expires_at": "2026-06-09T00:00:00Z",
            "max_chunk_bytes": 67108864,
        }),
    );
    let chunk_ack = |idx: u32, complete: bool| {
        StubResponse::json(
            200,
            serde_json::json!({ "index": idx, "received": [idx], "remaining": 0, "complete": complete }),
        )
    };
    let complete = StubResponse::json(
        200,
        serde_json::json!({
            "ok": true, "uri": "ar://default-key-tx", "sha256": whole_hex, "bytes": 250, "charged_usd_micros": 3,
        }),
    );

    let transport = Box::new(MockTransport::new(vec![
        create,
        chunk_ack(0, false),
        chunk_ack(1, false),
        chunk_ack(2, true),
        complete,
    ]));
    let (client, ptr) = client_with("https://gw.example.com", Some(&bearer_key()), transport);

    let mut input = resumable_input(content.clone());
    input.threshold_bytes = Some(5);
    input.chunk_bytes = Some(100);
    // No idempotency_key supplied -> the helper must derive the default.
    assert!(input.idempotency_key.is_none());
    let result = client.poe().upload_resumable(&input).unwrap();
    assert_eq!(result.uri, "ar://default-key-tx");

    // The /complete request carried the derived default key, byte-identical to the
    // `resumable-<sha256hex>` scheme shared with the TypeScript SDK.
    let complete_req = mock(ptr).nth(4);
    assert!(complete_req.url.ends_with("/complete"));
    let expected_key = format!("resumable-{whole_hex}");
    assert_eq!(
        header(&complete_req, "idempotency-key").as_deref(),
        Some(expected_key.as_str()),
        "default completion key must be resumable-<declared sha256 hex>"
    );
}

#[test]
fn complete_caller_supplied_idempotency_key_overrides_the_default() {
    // An explicit idempotency key the caller passes must be sent verbatim on
    // /complete, NOT replaced by the derived default.
    let content: Vec<u8> = (0u8..250).collect();
    let whole_hex = sha256_hex(&content);

    let create = StubResponse::json(
        201,
        serde_json::json!({
            "session_id": "01956b41-7c00-7000-8000-000000000555",
            "chunk_bytes": 100,
            "chunk_count": 3,
            "received": [],
            "expires_at": "2026-06-09T00:00:00Z",
            "max_chunk_bytes": 67108864,
        }),
    );
    let chunk_ack = |idx: u32, complete: bool| {
        StubResponse::json(
            200,
            serde_json::json!({ "index": idx, "received": [idx], "remaining": 0, "complete": complete }),
        )
    };
    let complete = StubResponse::json(
        200,
        serde_json::json!({
            "ok": true, "uri": "ar://explicit-key-tx", "sha256": whole_hex, "bytes": 250, "charged_usd_micros": 3,
        }),
    );

    let transport = Box::new(MockTransport::new(vec![
        create,
        chunk_ack(0, false),
        chunk_ack(1, false),
        chunk_ack(2, true),
        complete,
    ]));
    let (client, ptr) = client_with("https://gw.example.com", Some(&bearer_key()), transport);

    let mut input = resumable_input(content);
    input.threshold_bytes = Some(5);
    input.chunk_bytes = Some(100);
    input.idempotency_key = Some("caller-chosen-key".to_string());
    client.poe().upload_resumable(&input).unwrap();

    let complete_req = mock(ptr).nth(4);
    assert_eq!(
        header(&complete_req, "idempotency-key").as_deref(),
        Some("caller-chosen-key"),
        "an explicit key must not be overridden by the default"
    );
}

// ---------------------------------------------------------------------------
// 402 insufficient-storage-credit at create -> funding error (all 402 codes)
// ---------------------------------------------------------------------------

#[test]
fn create_402_storage_credit_surfaces_funding_error() {
    // A 402 at create with the `insufficient-storage-credit` code (one of the three
    // funding/affordability codes the gateway can return alongside
    // `insufficient-funds` and `no-funding-grant`) maps to the SAME typed funding
    // error as `insufficient-funds`: the funding mapping is keyed on the 402 status,
    // so every funding code surfaces consistently. No chunk flows.
    let content: Vec<u8> = (0u8..200).collect();
    let problem = problem_body(serde_json::json!({
        "status": 402,
        "code": "insufficient-storage-credit",
        "title": "Payment Required",
        "detail": "the drawable storage credit is below the safety floor",
    }));
    let transport = Box::new(MockTransport::single(StubResponse::json(402, problem)));
    let (client, ptr) = client_with("https://gw.example.com", Some(&bearer_key()), transport);

    let mut input = resumable_input(content);
    input.threshold_bytes = Some(5);
    input.chunk_bytes = Some(100);
    let err = client.poe().upload_resumable(&input).unwrap_err();

    match err {
        ResumableUploadError::InsufficientFunds(problem) => {
            assert_eq!(problem.http_status(), 402);
            assert_eq!(problem.code(), "insufficient-storage-credit");
        }
        other => panic!("expected InsufficientFunds for a 402 funding code, got {other:?}"),
    }
    assert_eq!(mock(ptr).call_count(), 1, "rejected before any chunk");
}
