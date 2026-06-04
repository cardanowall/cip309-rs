//! Shared request-building and response-handling plumbing for the namespaces.
//!
//! The three namespaces (`poe`, `records`, `account`) and the publish helpers
//! all build the same auth/content headers, parse the JSON body the same way,
//! and raise the same typed [`Label309HttpError`] on a non-2xx response. That
//! logic lives here once.

use crate::client::errors::{parse_http_error, Label309HttpError, ParseHttpErrorArgs};
use crate::client::transport::{ClientResponse, ClientTransport, RequestBody};
use crate::verifier::fetch::{HttpMethod, OutboundError};

/// The error a namespace call returns: a typed HTTP error from the gateway, or a
/// transport/egress failure.
///
/// The [`Label309HttpError`] is boxed because it carries the full RFC 7807
/// document; the box keeps `Result<T, ClientError>` small on the success path.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// A typed RFC 7807 error from the gateway (non-2xx response).
    #[error(transparent)]
    Http(#[from] Box<Label309HttpError>),
    /// An outbound egress failure (deny-host, protocol/method, over-cap body, or
    /// a transport error).
    #[error(transparent)]
    Outbound(#[from] OutboundError),
    /// The success body could not be parsed into the expected response type.
    #[error("failed to parse response body: {0}")]
    Decode(String),
}

/// The resolved per-namespace configuration: the opaque bearer key, the gateway
/// base URL (trailing slash stripped), and the shared transport.
pub struct NamespaceConfig<'t> {
    /// The opaque bearer key, forwarded as `Authorization: Bearer <key>`.
    pub api_key: Option<String>,
    /// The gateway base URL with any single trailing slash removed.
    pub base_url: String,
    /// The shared outbound transport.
    pub transport: &'t dyn ClientTransport,
}

/// JSON request headers: `content-type` + `accept` + optional bearer +
/// optional idempotency key.
#[must_use]
pub fn json_headers(api_key: Option<&str>, idempotency_key: Option<&str>) -> Vec<(String, String)> {
    let mut headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("accept".to_string(), "application/json".to_string()),
    ];
    if let Some(key) = api_key {
        headers.push(("authorization".to_string(), format!("Bearer {key}")));
    }
    if let Some(idem) = idempotency_key {
        headers.push(("idempotency-key".to_string(), idem.to_string()));
    }
    headers
}

/// Multipart request headers: `accept` + optional bearer + optional idempotency
/// key. The content-type is set by the transport (it carries the boundary).
#[must_use]
pub fn multipart_headers(
    api_key: Option<&str>,
    idempotency_key: Option<&str>,
) -> Vec<(String, String)> {
    let mut headers = vec![("accept".to_string(), "application/json".to_string())];
    if let Some(key) = api_key {
        headers.push(("authorization".to_string(), format!("Bearer {key}")));
    }
    if let Some(idem) = idempotency_key {
        headers.push(("idempotency-key".to_string(), idem.to_string()));
    }
    headers
}

/// Parse a JSON response body, returning `None` for an empty or non-JSON body.
fn read_json(body: &[u8]) -> Option<serde_json::Value> {
    if body.is_empty() {
        return None;
    }
    serde_json::from_slice(body).ok()
}

/// Raise the most-specific [`HttpError`] on a non-2xx response; otherwise return
/// the response for the caller to read.
fn throw_if_not_ok(response: ClientResponse) -> Result<ClientResponse, ClientError> {
    if (200..300).contains(&response.status) {
        return Ok(response);
    }
    let body = read_json(&response.body);
    Err(ClientError::Http(Box::new(parse_http_error(
        ParseHttpErrorArgs {
            http_status: response.status,
            body,
            request_id: response.headers.request_id.clone(),
            retry_after_seconds: response.headers.retry_after_seconds,
        },
    ))))
}

/// Send a request through the transport, then raise the typed error on a non-2xx
/// status. On success the raw [`ClientResponse`] is returned so the caller can
/// read the body (and the HTTP status, for dedup-hit detection).
pub fn send(
    transport: &dyn ClientTransport,
    url: &str,
    method: HttpMethod,
    headers: &[(String, String)],
    body: &RequestBody,
) -> Result<ClientResponse, ClientError> {
    let response = transport.send(url, method, headers, body)?;
    throw_if_not_ok(response)
}

/// Deserialize a success body into `T`.
pub fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, ClientError> {
    serde_json::from_slice(body).map_err(|e| ClientError::Decode(e.to_string()))
}
