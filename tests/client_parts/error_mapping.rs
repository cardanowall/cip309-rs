// RFC 7807 error-mapping cases, ported from the TypeScript / Python
// `http-error` and per-error tests. Each case feeds a problem+json document to
// `parse_http_error` and asserts the exact typed kind, status, request id, and
// projected extension fields. A second group drives the same mapping through a
// real publish/quote call so the namespace error path is covered end to end.

fn parse(status: u16, body: serde_json::Value) -> Label309HttpError {
    parse_http_error(ParseHttpErrorArgs {
        http_status: status,
        body: Some(body),
        request_id: None,
        retry_after_seconds: None,
    })
}

fn parse_with(status: u16, body: serde_json::Value, request_id: Option<&str>, retry: Option<u64>) -> Label309HttpError {
    parse_http_error(ParseHttpErrorArgs {
        http_status: status,
        body: Some(body),
        request_id: request_id.map(str::to_string),
        retry_after_seconds: retry,
    })
}

#[test]
fn envelope_projection_preserves_problem_and_splits_extensions() {
    let body = problem_body(serde_json::json!({
        "type": "https://cardanowall.com/problems/insufficient-funds",
        "title": "Payment Required",
        "status": 402,
        "detail": "Required $0.18 for this publish; balance is $0.05.",
        "code": "insufficient-funds",
        "balance_usd_micros": "50000",
        "required_usd_micros": "180000",
        "top_up_url": "/billing/top-up",
    }));
    let err = parse_with(402, body, Some("req-1"), None);
    assert_eq!(err.code(), "insufficient-funds");
    assert_eq!(err.http_status(), 402);
    assert_eq!(err.problem().title, "Payment Required");
    assert_eq!(
        err.problem().detail,
        "Required $0.18 for this publish; balance is $0.05."
    );
    assert_eq!(
        err.problem().r#type,
        "https://cardanowall.com/problems/insufficient-funds"
    );
    assert_eq!(err.problem().trace_id, "01977c00-0000-7000-8000-000000000000");
    assert_eq!(err.request_id(), "req-1");
    // Extensions split out cleanly:
    assert_eq!(err.problem().extension_str("top_up_url").as_deref(), Some("/billing/top-up"));
    assert!(err.problem().extensions.contains_key("balance_usd_micros"));
    assert!(!err.problem().extensions.contains_key("code"));
    // Error message defaults to the detail.
    assert_eq!(err.to_string(), "Required $0.18 for this publish; balance is $0.05.");
    // Typed projection:
    match err.kind() {
        HttpErrorKind::InsufficientFunds {
            balance_usd_micros,
            required_usd_micros,
            top_up_url,
        } => {
            assert_eq!(*balance_usd_micros, Some(50_000));
            assert_eq!(*required_usd_micros, Some(180_000));
            assert_eq!(top_up_url.as_deref(), Some("/billing/top-up"));
        }
        other => panic!("expected InsufficientFunds, got {other:?}"),
    }
}

#[test]
fn request_id_falls_back_to_trace_id_when_header_absent() {
    let err = parse(
        500,
        problem_body(serde_json::json!({ "code": "internal-error", "status": 500, "trace_id": "trace-xyz" })),
    );
    assert_eq!(err.request_id(), "trace-xyz");
}

#[test]
fn non_conforming_body_synthesises_a_problem() {
    let err = parse_http_error(ParseHttpErrorArgs {
        http_status: 418,
        body: None,
        request_id: None,
        retry_after_seconds: None,
    });
    assert_eq!(err.code(), "http-418");
    assert_eq!(err.http_status(), 418);
    assert_eq!(err.problem().r#type, "about:blank");
    assert!(matches!(err.kind(), HttpErrorKind::Other));
}

#[test]
fn retry_after_forwards_to_rate_limited() {
    let err = parse_with(
        429,
        problem_body(serde_json::json!({ "code": "rate-limited", "status": 429 })),
        None,
        Some(42),
    );
    assert!(matches!(err.kind(), HttpErrorKind::RateLimited));
    assert_eq!(err.retry_after_seconds(), Some(42));
}

#[test]
fn dispatch_by_code_covers_the_full_catalogue() {
    // unauthorized
    assert!(matches!(
        parse(401, problem_body(serde_json::json!({ "code": "unauthorized", "status": 401 }))).kind(),
        HttpErrorKind::Unauthorized
    ));
    // forbidden + csrf-invalid → Forbidden (the latter keeps its own code)
    let csrf = parse(403, problem_body(serde_json::json!({ "code": "csrf-invalid", "status": 403 })));
    assert!(matches!(csrf.kind(), HttpErrorKind::Forbidden));
    assert_eq!(csrf.code(), "csrf-invalid");
    assert!(matches!(
        parse(403, problem_body(serde_json::json!({ "code": "forbidden", "status": 403 }))).kind(),
        HttpErrorKind::Forbidden
    ));
    // insufficient-scope
    let scope = parse(
        403,
        problem_body(serde_json::json!({
            "code": "insufficient-scope", "status": 403,
            "required": ["poe:create"], "granted": ["poe:read", "account:read"],
        })),
    );
    match scope.kind() {
        HttpErrorKind::InsufficientScope { required_scopes, granted_scopes } => {
            assert_eq!(required_scopes, &["poe:create"]);
            assert_eq!(granted_scopes, &["poe:read", "account:read"]);
        }
        other => panic!("expected InsufficientScope, got {other:?}"),
    }
    // quote-expired / quote-not-found / quote-already-consumed carry quote_id
    for code in ["quote-expired", "quote-not-found", "quote-already-consumed"] {
        let err = parse(
            410,
            problem_body(serde_json::json!({ "code": code, "status": 410, "quote_id": QUOTE_ID })),
        );
        let quote_id = match err.kind() {
            HttpErrorKind::QuoteExpired { quote_id }
            | HttpErrorKind::QuoteNotFound { quote_id }
            | HttpErrorKind::QuoteAlreadyConsumed { quote_id } => quote_id.clone(),
            other => panic!("expected a quote error for {code}, got {other:?}"),
        };
        assert_eq!(quote_id.as_deref(), Some(QUOTE_ID));
    }
    // not-found vs record-not-found
    assert!(matches!(
        parse(404, problem_body(serde_json::json!({ "code": "not-found", "status": 404 }))).kind(),
        HttpErrorKind::NotFound
    ));
    assert!(matches!(
        parse(404, problem_body(serde_json::json!({ "code": "record-not-found", "status": 404 }))).kind(),
        HttpErrorKind::RecordNotFound
    ));
    // idempotency-key-conflict
    assert!(matches!(
        parse(409, problem_body(serde_json::json!({ "code": "idempotency-key-conflict", "status": 409 }))).kind(),
        HttpErrorKind::IdempotencyConflict
    ));
    // validation-failed carries errors[]
    let vf = parse(
        422,
        problem_body(serde_json::json!({
            "code": "validation-failed", "status": 422,
            "errors": [
                { "field": "items.0.hashes", "code": "invalid_type", "detail": "Expected object" },
                { "field": "", "code": "custom", "detail": "Body-level rule failed" },
            ],
        })),
    );
    assert!(matches!(vf.kind(), HttpErrorKind::ValidationFailed));
    let errors = vf.problem().errors.as_ref().unwrap();
    assert_eq!(errors.len(), 2);
    assert_eq!(errors[0].field, "items.0.hashes");
    assert_eq!(errors[1].field, "");
    // invalid-body / malformed-cbor
    assert!(matches!(
        parse(400, problem_body(serde_json::json!({ "code": "invalid-body", "status": 400 }))).kind(),
        HttpErrorKind::InvalidBody
    ));
    assert!(matches!(
        parse(400, problem_body(serde_json::json!({ "code": "malformed-cbor", "status": 400 }))).kind(),
        HttpErrorKind::MalformedCbor
    ));
    // batch-too-large carries max/got
    let bt = parse(400, problem_body(serde_json::json!({ "code": "batch-too-large", "status": 400, "max": 50, "got": 73 })));
    match bt.kind() {
        HttpErrorKind::BatchTooLarge { max, got } => {
            assert_eq!(*max, Some(50));
            assert_eq!(*got, Some(73));
        }
        other => panic!("expected BatchTooLarge, got {other:?}"),
    }
    // batch-empty / internal-error
    assert!(matches!(
        parse(400, problem_body(serde_json::json!({ "code": "batch-empty", "status": 400 }))).kind(),
        HttpErrorKind::BatchEmpty
    ));
    assert!(matches!(
        parse(500, problem_body(serde_json::json!({ "code": "internal-error", "status": 500 }))).kind(),
        HttpErrorKind::InternalServer
    ));
    // service-unavailable carries Retry-After
    let su = parse_with(503, problem_body(serde_json::json!({ "code": "service-unavailable", "status": 503 })), None, Some(30));
    assert!(matches!(su.kind(), HttpErrorKind::ServiceUnavailable));
    assert_eq!(su.retry_after_seconds(), Some(30));
    // A gateway's transient `fx-stale` pricing outage collapses to the
    // vendor-neutral service-unavailable condition (no FX-specific surface).
    let fx = parse(503, problem_body(serde_json::json!({ "code": "fx-stale", "status": 503 })));
    assert!(matches!(fx.kind(), HttpErrorKind::ServiceUnavailable));
    assert_eq!(fx.code(), "fx-stale");
}

#[test]
fn errors_array_skips_non_object_entries_and_keeps_valid_ones() {
    // A hostile / sloppy gateway interleaves non-object junk into errors[]. The
    // reference projection iterates, skips non-objects, and coerces missing string
    // fields to "" — it must NOT discard the whole array on one bad element.
    let vf = parse(
        422,
        problem_body(serde_json::json!({
            "code": "validation-failed", "status": 422,
            "errors": [
                "this is not an object",
                { "field": "items.0.hashes", "code": "invalid_type", "detail": "Expected object" },
                42,
                { "code": "custom" },
                null,
            ],
        })),
    );
    assert!(matches!(vf.kind(), HttpErrorKind::ValidationFailed));
    let errors = vf.problem().errors.as_ref().expect("errors[] present");
    // Two object entries survive; the string, number, and null are skipped.
    assert_eq!(errors.len(), 2);
    assert_eq!(errors[0].field, "items.0.hashes");
    assert_eq!(errors[0].code, "invalid_type");
    assert_eq!(errors[0].detail, "Expected object");
    // Missing string fields default to "" rather than dropping the entry.
    assert_eq!(errors[1].field, "");
    assert_eq!(errors[1].code, "custom");
    assert_eq!(errors[1].detail, "");
}

#[test]
fn errors_non_array_is_none_but_empty_array_is_some_empty() {
    // Not an array → None (no errors projection).
    let not_array = parse(
        422,
        problem_body(serde_json::json!({
            "code": "validation-failed", "status": 422, "errors": "nope",
        })),
    );
    assert!(not_array.problem().errors.is_none());

    // An array of only-junk → Some([]) (an empty-but-present projection), matching
    // the reference's "array in, list out (possibly empty)" contract.
    let only_junk = parse(
        422,
        problem_body(serde_json::json!({
            "code": "validation-failed", "status": 422, "errors": [1, "x", null],
        })),
    );
    let errors = only_junk.problem().errors.as_ref().expect("array → Some");
    assert!(errors.is_empty());
}

#[test]
fn out_of_range_status_saturates_instead_of_wrapping() {
    // A hostile body claims an absurd `status` (> u16::MAX). It must clamp to
    // u16::MAX, never wrap modulo 2^16 into a misleadingly small status (99999 mod
    // 2^16 would otherwise be 34463).
    let err = parse(
        500,
        problem_body(serde_json::json!({ "code": "internal-error", "status": 99999 })),
    );
    assert_eq!(err.problem().status, u16::MAX);
    assert_ne!(err.problem().status, 99999u32 as u16);
}

#[test]
fn unknown_code_falls_through_to_other_with_verbatim_body() {
    let err = parse(451, problem_body(serde_json::json!({ "code": "unavailable-for-legal-reasons", "status": 451 })));
    assert!(matches!(err.kind(), HttpErrorKind::Other));
    assert_eq!(err.code(), "unavailable-for-legal-reasons");
}

// ---------------------------------------------------------------------------
// Same mapping through the namespace path (end to end)
// ---------------------------------------------------------------------------

/// Extract the typed `Label309HttpError` from a `ClientError`, panicking otherwise.
fn http_err(err: ClientError) -> Label309HttpError {
    match err {
        ClientError::Http(boxed) => *boxed,
        other => panic!("expected ClientError::Http, got {other:?}"),
    }
}

#[test]
fn publish_surfaces_insufficient_funds_with_bigint_money_fields() {
    let body = problem_body(serde_json::json!({
        "code": "insufficient-funds", "status": 402, "title": "Payment Required",
        "detail": "Required $0.18; balance $0.00.",
        "balance_usd_micros": "0", "required_usd_micros": "180000", "top_up_url": "/billing/top-up",
    }));
    let transport = Box::new(MockTransport::single(StubResponse::json(402, body)));
    let (client, _) = client_with("http://test", Some(&bearer_key()), transport);
    let err = client
        .poe()
        .publish(&PublishInput {
            record: vec![0xaa],
            quote_id: QUOTE_ID.to_string(),
            signatures: None,
            idempotency_key: None,
        })
        .unwrap_err();
    let err = http_err(err);
    match err.kind() {
        HttpErrorKind::InsufficientFunds { balance_usd_micros, required_usd_micros, top_up_url } => {
            assert_eq!(*balance_usd_micros, Some(0));
            assert_eq!(*required_usd_micros, Some(180_000));
            assert_eq!(top_up_url.as_deref(), Some("/billing/top-up"));
        }
        other => panic!("expected InsufficientFunds, got {other:?}"),
    }
}

#[test]
fn publish_surfaces_rate_limited_with_retry_after_header() {
    let body = problem_body(serde_json::json!({ "code": "rate-limited", "status": 429, "title": "Too Many Requests" }));
    let transport = Box::new(MockTransport::single(
        StubResponse::json(429, body).with_retry_after(7),
    ));
    let (client, _) = client_with("http://test", Some(&bearer_key()), transport);
    let err = http_err(
        client
            .poe()
            .publish(&PublishInput {
                record: vec![0xaa],
                quote_id: QUOTE_ID.to_string(),
                signatures: None,
                idempotency_key: None,
            })
            .unwrap_err(),
    );
    assert!(matches!(err.kind(), HttpErrorKind::RateLimited));
    assert_eq!(err.retry_after_seconds(), Some(7));
}

#[test]
fn internal_error_threads_x_request_id_header() {
    let body = problem_body(serde_json::json!({ "code": "internal-error", "status": 500, "title": "Internal Server Error" }));
    let transport = Box::new(MockTransport::single(
        StubResponse::json(500, body).with_request_id("req-correlate"),
    ));
    let (client, _) = client_with("http://test", Some(&bearer_key()), transport);
    let err = http_err(
        client
            .poe()
            .publish(&PublishInput {
                record: vec![0xaa],
                quote_id: QUOTE_ID.to_string(),
                signatures: None,
                idempotency_key: None,
            })
            .unwrap_err(),
    );
    assert_eq!(err.request_id(), "req-correlate");
}

#[test]
fn quote_surfaces_fx_stale_as_service_unavailable() {
    // A gateway pricing on a live FX oracle may emit a transient `fx-stale`
    // outage. The vendor-neutral client collapses it to a service-unavailable
    // condition: there is no FX-specific surface on a gateway-agnostic SDK.
    let body = problem_body(serde_json::json!({
        "code": "fx-stale", "status": 503, "title": "Service Unavailable",
        "detail": "No fresh FX snapshot.",
    }));
    let transport = Box::new(MockTransport::single(StubResponse::json(503, body)));
    let (client, _) = client_with("http://test", Some(&bearer_key()), transport);
    let err = http_err(
        client
            .poe()
            .quote(&QuoteInput {
                record_bytes: 256,
                recipient_count: 0,
                file_bytes_total: 0,
            })
            .unwrap_err(),
    );
    assert!(matches!(err.kind(), HttpErrorKind::ServiceUnavailable));
    assert_eq!(err.code(), "fx-stale");
}
