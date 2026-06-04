//! The client's outbound HTTP layer, built on the verifier's single egress.
//!
//! Every request the client sends is routed through
//! [`wrap_fetch_outbound`] over a
//! [`FetchTransport`], so the
//! deny-host policy, the protocol/method allowlist, the bounded response-body
//! cap, and the per-call audit trail all apply to client traffic exactly as they
//! do to verifier traffic — there is no second egress.
//!
//! The verifier transport returns only a status and a body. The HTTP-error
//! mapping additionally needs two response headers (`X-Request-Id` and
//! `Retry-After`). Rather than open a second code path, the production transport
//! ([`ReqwestClientTransport`]) implements `FetchTransport` and stashes those two
//! headers in an internal cell as it reads the response; the client reads them
//! back after `wrap_fetch_outbound` returns. The `/uploads` multipart body is
//! held in that same inner transport (it cannot ride the egress's string body),
//! so multipart still flows through the deny-host / protocol pre-flight. Tests
//! substitute a capturing `ClientTransport` and assert the outgoing request
//! directly.

use std::sync::Mutex;

use crate::verifier::fetch::{
    wrap_fetch_outbound, FetchOutboundOptions, FetchTransport, HttpMethod, HttpPurpose,
    OutboundError, RetryConfig, ThreadSleepClock, WrapFetchOutboundConfig,
};

/// One field of a multipart `/uploads` form.
#[derive(Debug, Clone)]
pub struct MultipartField {
    /// The form field name (e.g. `target`, `file_0`).
    pub name: String,
    /// The optional filename (`Some` for binary blobs, `None` for text fields).
    pub filename: Option<String>,
    /// The optional MIME type (e.g. `application/octet-stream`).
    pub content_type: Option<String>,
    /// The field's raw bytes.
    pub value: Vec<u8>,
}

/// The body of a client request.
#[derive(Debug, Clone)]
pub enum RequestBody {
    /// No body (e.g. a `GET`).
    None,
    /// A compact-JSON string body.
    Json(String),
    /// A multipart form body (the `/uploads` path).
    Multipart(Vec<MultipartField>),
}

/// The fixed multipart boundary the client emits.
///
/// `reqwest`'s `multipart` cargo feature is not enabled, so the form body is
/// serialised by hand with this boundary. The token is opaque and never appears
/// in any field value, so a fixed value is safe; the gateway parses the boundary
/// out of the `Content-Type` header.
const MULTIPART_BOUNDARY: &str = "label309sdkrsboundaryV1aaaaaaaaaa";

/// Serialise multipart fields into the raw `multipart/form-data` body bytes.
fn encode_multipart(fields: &[MultipartField]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for field in fields {
        out.extend_from_slice(b"--");
        out.extend_from_slice(MULTIPART_BOUNDARY.as_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(b"Content-Disposition: form-data; name=\"");
        out.extend_from_slice(field.name.as_bytes());
        out.push(b'"');
        if let Some(filename) = &field.filename {
            out.extend_from_slice(b"; filename=\"");
            out.extend_from_slice(filename.as_bytes());
            out.push(b'"');
        }
        out.extend_from_slice(b"\r\n");
        if let Some(ct) = &field.content_type {
            out.extend_from_slice(b"Content-Type: ");
            out.extend_from_slice(ct.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&field.value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"--");
    out.extend_from_slice(MULTIPART_BOUNDARY.as_bytes());
    out.extend_from_slice(b"--\r\n");
    out
}

/// The response headers the HTTP-error mapping consumes.
#[derive(Debug, Clone, Default)]
pub struct ResponseHeaders {
    /// `X-Request-Id` response header, when present.
    pub request_id: Option<String>,
    /// `Retry-After` response header parsed as integer seconds, when present.
    pub retry_after_seconds: Option<u64>,
}

/// A no-op jitter source: the client never retries, so jitter is never read.
struct UnitJitter;

impl crate::verifier::fetch::Jitter for UnitJitter {
    fn multiplier(&self, _attempt_index: usize) -> f64 {
        1.0
    }
}

/// One client-level HTTP response: status, body, and the two error-mapping
/// headers.
#[derive(Debug, Clone)]
pub struct ClientResponse {
    /// HTTP status code.
    pub status: u16,
    /// The response body bytes (already bounded by the egress size cap).
    pub body: Vec<u8>,
    /// The `X-Request-Id` / `Retry-After` headers the error mapping reads.
    pub headers: ResponseHeaders,
}

/// A transport that can also surface the two response headers the error mapping
/// needs.
///
/// The production path is [`ReqwestClientTransport`]; tests implement this
/// directly to stub responses and capture requests.
pub trait ClientTransport {
    /// Perform one request and return the status, body, and error-mapping
    /// headers.
    ///
    /// # Errors
    ///
    /// Returns the egress [`OutboundError`] for a deny-host short circuit, a
    /// protocol/method rejection, an over-cap body, or a transport failure.
    fn send(
        &self,
        url: &str,
        method: HttpMethod,
        headers: &[(String, String)],
        body: &RequestBody,
    ) -> Result<ClientResponse, OutboundError>;
}

/// The production transport: a header-capturing `reqwest` transport routed
/// through the verifier egress.
///
/// Deny-host patterns default to none for the client (the gateway base URL is
/// the caller's own chosen host, not a third-party storage endpoint).
#[derive(Default)]
pub struct ReqwestClientTransport {
    deny_hosts: Vec<String>,
}

impl ReqwestClientTransport {
    /// A transport with no deny-host patterns (the client default).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A transport that rejects the supplied deny-host patterns.
    #[must_use]
    pub fn with_deny_hosts(deny_hosts: Vec<String>) -> Self {
        Self { deny_hosts }
    }
}

/// A `FetchTransport` that performs a blocking `reqwest` request, carries the
/// out-of-band multipart payload, and stashes the two error-mapping headers as
/// it reads the response.
struct HeaderCapturingTransport {
    /// The pre-serialised multipart body and its boundary content-type, set on
    /// the `/uploads` path. `reqwest`'s `multipart` feature is not enabled, so
    /// the body is hand-encoded and sent as raw bytes here.
    multipart: Option<(Vec<u8>, String)>,
    captured: Mutex<ResponseHeaders>,
}

impl FetchTransport for HeaderCapturingTransport {
    fn fetch(
        &self,
        url: &str,
        opts: &FetchOutboundOptions,
    ) -> Result<crate::verifier::fetch::FetchOutboundResult, OutboundError> {
        let started = std::time::Instant::now();
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(
                crate::verifier::fetch::DEFAULT_TIMEOUT_MS,
            ))
            // Never follow redirects: the deny-host / SSRF guard checks only the
            // original URL, so an un-rechecked `Location` hop could pivot into a
            // blocked host. A 3xx surfaces as a non-2xx status to the caller.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| OutboundError::Transport {
                url: String::new(),
                message: e.to_string(),
            })?;

        let method = match opts.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
        };
        let mut req = client.request(method, url);
        for (k, v) in &opts.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some((raw, content_type)) = &self.multipart {
            // The boundary content-type carries the multipart boundary; the
            // header list deliberately omits any content-type for this path.
            req = req
                .header("content-type", content_type.as_str())
                .body(raw.clone());
        } else if let Some(body) = &opts.body {
            req = req.body(body.clone());
        }

        let resp = req.send().map_err(|e| OutboundError::Transport {
            url: url.to_string(),
            message: e.to_string(),
        })?;
        let status = resp.status().as_u16();

        let request_id = resp
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let retry_after_seconds = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok());
        if let Ok(mut slot) = self.captured.lock() {
            *slot = ResponseHeaders {
                request_id,
                retry_after_seconds,
            };
        }

        let max_bytes = opts
            .max_bytes
            .unwrap_or(crate::verifier::fetch::DEFAULT_OUTBOUND_MAX_BYTES);
        let bytes = read_body_capped(resp, url, max_bytes)?;
        Ok(crate::verifier::fetch::FetchOutboundResult {
            status,
            bytes,
            duration_ms: started.elapsed().as_millis() as u64,
        })
    }
}

/// Stream the response body, aborting the instant the running total exceeds the
/// cap. The size guard never trusts `Content-Length`.
fn read_body_capped(
    mut resp: reqwest::blocking::Response,
    url: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, OutboundError> {
    use std::io::Read;
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = resp.read(&mut buf).map_err(|e| OutboundError::Transport {
            url: url.to_string(),
            message: e.to_string(),
        })?;
        if n == 0 {
            break;
        }
        if out.len() as u64 + n as u64 > max_bytes {
            return Err(OutboundError::BodyTooLarge {
                url: url.to_string(),
                limit_bytes: max_bytes,
            });
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

impl ClientTransport for ReqwestClientTransport {
    fn send(
        &self,
        url: &str,
        method: HttpMethod,
        headers: &[(String, String)],
        body: &RequestBody,
    ) -> Result<ClientResponse, OutboundError> {
        let (string_body, multipart) = match body {
            RequestBody::None => (None, None),
            RequestBody::Json(s) => (Some(s.clone()), None),
            RequestBody::Multipart(fields) => {
                let raw = encode_multipart(fields);
                let content_type = format!("multipart/form-data; boundary={MULTIPART_BOUNDARY}");
                (None, Some((raw, content_type)))
            }
        };
        let inner = HeaderCapturingTransport {
            multipart,
            captured: Mutex::new(ResponseHeaders::default()),
        };
        let mut audit = Vec::new();
        let config = WrapFetchOutboundConfig {
            deny_hosts: self.deny_hosts.clone(),
            retry: RetryConfig {
                retries: 0,
                ..RetryConfig::default()
            },
        };
        let mut opts = FetchOutboundOptions::new(method, HttpPurpose::Https);
        opts.headers = headers.to_vec();
        opts.body = string_body;

        let result = wrap_fetch_outbound(
            &inner,
            &mut audit,
            &config,
            &ThreadSleepClock,
            &UnitJitter,
            url,
            &opts,
        )?;
        let captured = inner.captured.lock().map(|g| g.clone()).unwrap_or_default();
        Ok(ClientResponse {
            status: result.status,
            body: result.bytes,
            headers: captured,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{encode_multipart, MultipartField, MULTIPART_BOUNDARY};

    /// Pin the exact `/uploads` wire bytes. `reqwest`'s `multipart` feature is
    /// disabled, so `encode_multipart` is the production body encoder; a
    /// boundary/CRLF regression here would silently corrupt every upload. The
    /// snapshot is asserted as a UTF-8 string so a CRLF drift is legible in the
    /// failure diff (every field value here is printable ASCII).
    #[test]
    fn encode_multipart_emits_exact_rfc2046_bytes() {
        let fields = vec![
            MultipartField {
                name: "target".to_string(),
                filename: None,
                content_type: None,
                value: b"arweave".to_vec(),
            },
            MultipartField {
                name: "file_0".to_string(),
                filename: Some("file_0.bin".to_string()),
                content_type: Some("application/octet-stream".to_string()),
                value: b"AB".to_vec(),
            },
            MultipartField {
                name: "file_1".to_string(),
                filename: Some("file_1.bin".to_string()),
                content_type: Some("application/octet-stream".to_string()),
                value: b"CD".to_vec(),
            },
        ];

        let raw = encode_multipart(&fields);
        let b = MULTIPART_BOUNDARY;
        let expected = format!(
            "--{b}\r\n\
             Content-Disposition: form-data; name=\"target\"\r\n\
             \r\n\
             arweave\r\n\
             --{b}\r\n\
             Content-Disposition: form-data; name=\"file_0\"; filename=\"file_0.bin\"\r\n\
             Content-Type: application/octet-stream\r\n\
             \r\n\
             AB\r\n\
             --{b}\r\n\
             Content-Disposition: form-data; name=\"file_1\"; filename=\"file_1.bin\"\r\n\
             Content-Type: application/octet-stream\r\n\
             \r\n\
             CD\r\n\
             --{b}--\r\n"
        );

        assert_eq!(
            String::from_utf8(raw.clone()).expect("encoder emits UTF-8 for ASCII inputs"),
            expected,
            "multipart wire bytes drifted (boundary / CRLF / header structure)"
        );

        // Cross-check structural invariants independent of the string snapshot:
        // CRLF-terminated, exactly one closing `--boundary--` delimiter, and a
        // leading `--boundary` opener per the three fields.
        assert!(raw.ends_with(format!("--{b}--\r\n").as_bytes()));
        let opener = format!("--{b}\r\n");
        let opener_count = expected.matches(&opener).count();
        assert_eq!(opener_count, 3, "one opening delimiter per field");
    }

    /// A binary (non-UTF-8) field value must pass through the encoder verbatim,
    /// framed by the same CRLF delimiters.
    #[test]
    fn encode_multipart_passes_binary_value_through_verbatim() {
        let fields = vec![MultipartField {
            name: "file_0".to_string(),
            filename: Some("file_0.bin".to_string()),
            content_type: Some("application/octet-stream".to_string()),
            value: vec![0x00, 0xff, 0x0d, 0x0a, 0xaa],
        }];
        let raw = encode_multipart(&fields);
        let b = MULTIPART_BOUNDARY;
        let header = format!(
            "--{b}\r\n\
             Content-Disposition: form-data; name=\"file_0\"; filename=\"file_0.bin\"\r\n\
             Content-Type: application/octet-stream\r\n\
             \r\n"
        );
        let mut expected = header.into_bytes();
        expected.extend_from_slice(&[0x00, 0xff, 0x0d, 0x0a, 0xaa]);
        expected.extend_from_slice(b"\r\n");
        expected.extend_from_slice(format!("--{b}--\r\n").as_bytes());
        assert_eq!(raw, expected);
    }
}
