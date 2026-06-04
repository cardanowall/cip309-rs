//! Parity tests for the gateway-agnostic HTTP client.
//!
//! These tests pin the exact request bytes the client emits against the shared
//! `poe-request` / `records-request` fixtures, port the RFC 7807 error-mapping
//! cases from the TypeScript / Python `http-error` and per-error tests, exercise
//! the records / publish / batch flows through a capturing transport, and
//! byte-pin the off-host signing helper against the shared
//! `cose/sign1-build.json` corpus. No fixtures are copied — the canonical trees
//! are path-referenced from the sibling packages.

mod common;

use std::sync::Mutex;

use cardanowall::client::{
    parse_http_error, AccountBalance, ClientError, ClientResponse, ClientTransport, HttpErrorKind,
    InvalidClientConfigError, Label309Client, Label309ClientConfig, Label309HttpError, MerkleLeaf,
    ParseHttpErrorArgs, PoeVerifyInput, PublishBatchEntry, PublishBatchInput,
    PublishBatchResultEntry, PublishContentInput, PublishInput, PublishMerkleInput,
    PublishPrehashedInput, PublishSealedInput, QuoteInput, RecordSignature, RecordsListInput,
    RequestBody, ResponseHeaders, SealedKemChoice, Signer, SignerError, SupportedHashAlg,
    UploadsInput,
};
use cardanowall::verifier::fetch::{HttpMethod, OutboundError};

// ---------------------------------------------------------------------------
// Capturing transport
// ---------------------------------------------------------------------------

/// One captured outgoing request, recorded by [`MockTransport`].
#[derive(Debug, Clone)]
struct Captured {
    url: String,
    method: HttpMethod,
    headers: Vec<(String, String)>,
    body: RequestBodySnapshot,
}

/// A snapshot of one multipart field for assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MultipartFieldSnapshot {
    name: String,
    filename: Option<String>,
    content_type: Option<String>,
    value: Vec<u8>,
}

/// A snapshot of the request body suitable for assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RequestBodySnapshot {
    None,
    Json(String),
    Multipart(Vec<MultipartFieldSnapshot>),
}

impl RequestBodySnapshot {
    fn from(body: &RequestBody) -> Self {
        match body {
            RequestBody::None => RequestBodySnapshot::None,
            RequestBody::Json(s) => RequestBodySnapshot::Json(s.clone()),
            RequestBody::Multipart(fields) => RequestBodySnapshot::Multipart(
                fields
                    .iter()
                    .map(|f| MultipartFieldSnapshot {
                        name: f.name.clone(),
                        filename: f.filename.clone(),
                        content_type: f.content_type.clone(),
                        value: f.value.clone(),
                    })
                    .collect(),
            ),
        }
    }

    fn as_json(&self) -> &str {
        match self {
            RequestBodySnapshot::Json(s) => s,
            _ => panic!("expected a JSON body, got {self:?}"),
        }
    }
}

/// A stubbed response the mock returns for the next request.
#[derive(Clone)]
struct StubResponse {
    status: u16,
    body: Vec<u8>,
    headers: ResponseHeaders,
}

impl StubResponse {
    fn json(status: u16, value: serde_json::Value) -> Self {
        Self {
            status,
            body: serde_json::to_vec(&value).unwrap(),
            headers: ResponseHeaders::default(),
        }
    }

    fn with_request_id(mut self, id: &str) -> Self {
        self.headers.request_id = Some(id.to_string());
        self
    }

    fn with_retry_after(mut self, seconds: u64) -> Self {
        self.headers.retry_after_seconds = Some(seconds);
        self
    }
}

/// A capturing transport: records every request and replays queued responses.
struct MockTransport {
    captured: Mutex<Vec<Captured>>,
    responses: Mutex<Vec<StubResponse>>,
}

impl MockTransport {
    fn new(responses: Vec<StubResponse>) -> Self {
        Self {
            captured: Mutex::new(Vec::new()),
            responses: Mutex::new(responses),
        }
    }

    fn single(response: StubResponse) -> Self {
        Self::new(vec![response])
    }

    fn first(&self) -> Captured {
        self.captured.lock().unwrap()[0].clone()
    }

    fn nth(&self, index: usize) -> Captured {
        self.captured.lock().unwrap()[index].clone()
    }

    fn call_count(&self) -> usize {
        self.captured.lock().unwrap().len()
    }
}

impl ClientTransport for MockTransport {
    fn send(
        &self,
        url: &str,
        method: HttpMethod,
        headers: &[(String, String)],
        body: &RequestBody,
    ) -> Result<ClientResponse, OutboundError> {
        self.captured.lock().unwrap().push(Captured {
            url: url.to_string(),
            method,
            headers: headers.to_vec(),
            body: RequestBodySnapshot::from(body),
        });
        let mut responses = self.responses.lock().unwrap();
        let stub = if responses.len() == 1 {
            responses[0].clone()
        } else {
            responses.remove(0)
        };
        Ok(ClientResponse {
            status: stub.status,
            body: stub.body,
            headers: stub.headers,
        })
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const QUOTE_ID: &str = "01956b41-7c00-7000-8000-000000000001";

/// An opaque bearer credential. The client forwards it verbatim and never
/// inspects its shape, so the test value can be any non-empty token.
fn bearer_key() -> String {
    "opaque-bearer-aaaa".to_string()
}

fn header(captured: &Captured, name: &str) -> Option<String> {
    captured
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

/// Build a client over a mock transport with an explicit base URL.
fn client_with(
    base_url: &str,
    api_key: Option<&str>,
    transport: Box<MockTransport>,
) -> (Label309Client, *const MockTransport) {
    let ptr: *const MockTransport = transport.as_ref();
    let client = Label309Client::with_transport(
        Label309ClientConfig {
            api_key: api_key.map(str::to_string),
            base_url: Some(base_url.to_string()),
        },
        transport,
    )
    .unwrap();
    (client, ptr)
}

/// Re-borrow the mock through the raw pointer captured at construction.
///
/// The client owns the boxed transport; the pointer lets the test inspect the
/// captured requests after the call without re-architecting ownership. Sound
/// because the box outlives every borrow here and is never moved.
fn mock<'a>(ptr: *const MockTransport) -> &'a MockTransport {
    unsafe { &*ptr }
}

fn problem_body(overrides: serde_json::Value) -> serde_json::Value {
    let mut base = serde_json::json!({
        "type": "https://cardanowall.com/problems/example",
        "title": "Example",
        "status": 400,
        "detail": "Example failure.",
        "code": "example",
        "trace_id": "01977c00-0000-7000-8000-000000000000",
    });
    if let (serde_json::Value::Object(b), serde_json::Value::Object(o)) = (&mut base, &overrides) {
        for (k, v) in o {
            b.insert(k.clone(), v.clone());
        }
    }
    base
}

fn publish_success_body() -> serde_json::Value {
    serde_json::json!({
        "id": "poe_06bqrjg0csvqfanaqexvqexvqc",
        "tx_hash": null,
        "status": "submitting",
        "items_count": 1,
        "signed": false,
        "sealed": false,
        "items": [],
        "conformance_profile": "core",
        "balance_after_usd_micros": "4500000",
    })
}

fn records_list_body(
    data: serde_json::Value,
    has_more: bool,
    next: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "object": "list",
        "data": data,
        "has_more": has_more,
        "next_cursor": next,
        "url": "/api/v1/records",
    })
}

include!("client_parts/request_parity.rs");
include!("client_parts/error_mapping.rs");
include!("client_parts/namespaces.rs");
include!("client_parts/off_host_sign.rs");
