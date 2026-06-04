//! RFC 7807 / RFC 9457 `application/problem+json` envelope and the typed error
//! catalogue the client raises on every non-2xx response.
//!
//! Every gateway `/api/v1/*` route emits the canonical shape
//!
//! ```json
//! {
//!   "type":     "https://<host>/problems/<code>",
//!   "title":    "Payment Required",
//!   "status":   402,
//!   "detail":   "Required $0.18 for this publish; balance is $0.05.",
//!   "code":     "insufficient-funds",
//!   "trace_id": "01977c00-0000-7000-8000-000000000000",
//!   "errors":   [{ "field": "items.0.hashes", "code": "invalid_type", "detail": "…" }]
//! }
//! ```
//!
//! plus any RFC 7807 §3.2 extension members (`balance_usd_micros`,
//! `required_usd_micros`, `top_up_url`, …). The `code` is the primary dispatch
//! key: [`parse_http_error`] maps each registered code to a specific
//! [`Label309HttpError`] variant that projects the relevant extension members onto
//! typed fields, and falls back to [`HttpErrorKind::Other`] (carrying the
//! verbatim document) for any code it does not recognise.

use serde::Deserialize;

/// An RFC 7807 per-field error entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ProblemErrorEntry {
    /// Dotted JSON path of the offending field; empty for body-level errors.
    #[serde(default)]
    pub field: String,
    /// Stable lowercase-kebab (or schema-issue) code for the specific failure.
    #[serde(default)]
    pub code: String,
    /// Human-readable explanation of this individual field error.
    #[serde(default)]
    pub detail: String,
}

/// The RFC 7807 `application/problem+json` document.
///
/// The canonical fields (`type`, `title`, `status`, `detail`, `code`,
/// `trace_id`) are always populated — [`parse_http_error`] synthesises them when
/// the server omits a field. Every non-canonical top-level member lands in
/// [`extensions`](ProblemDetails::extensions) as an RFC 7807 §3.2 extension.
#[derive(Debug, Clone, PartialEq)]
pub struct ProblemDetails {
    /// The problem type URI.
    pub r#type: String,
    /// Short, human-readable summary of the problem type.
    pub title: String,
    /// HTTP status code (mirrors the response status).
    pub status: u16,
    /// Human-readable explanation specific to this occurrence.
    pub detail: String,
    /// Stable lowercase-kebab problem code (the primary dispatch key).
    pub code: String,
    /// Trace identifier echoed on the `X-Request-Id` response header.
    pub trace_id: String,
    /// Per-field validation errors (present on `validation-failed`).
    pub errors: Option<Vec<ProblemErrorEntry>>,
    /// A URI that identifies the specific occurrence (RFC 7807 §3.1).
    pub instance: Option<String>,
    /// RFC 7807 §3.2 extension members, preserved verbatim.
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

/// The canonical RFC 7807 field names, used to split out extensions.
const CANONICAL_PROBLEM_KEYS: [&str; 8] = [
    "type", "title", "status", "detail", "code", "trace_id", "errors", "instance",
];

impl ProblemDetails {
    /// The default error message: the `detail`, or `"<title> (HTTP <status>)"`.
    #[must_use]
    pub fn message(&self) -> String {
        if self.detail.is_empty() {
            format!("{} (HTTP {})", self.title, self.status)
        } else {
            self.detail.clone()
        }
    }

    /// Read an extension member as a string.
    #[must_use]
    pub fn extension_str(&self, key: &str) -> Option<String> {
        self.extensions.get(key).and_then(|v| match v {
            serde_json::Value::String(s) => Some(s.clone()),
            _ => None,
        })
    }

    /// Read an extension member as a finite `u64` integer.
    ///
    /// Accepts a JSON number (when integral and non-negative).
    #[must_use]
    pub fn extension_u64(&self, key: &str) -> Option<u64> {
        self.extensions.get(key).and_then(serde_json::Value::as_u64)
    }

    /// Read an extension member as a decimal-string-encoded `u64`.
    ///
    /// Money fields cross the wire as decimal strings to preserve bigint
    /// precision; this parses them the way the reference SDKs do
    /// (`balance_usd_micros`, `required_usd_micros`).
    #[must_use]
    pub fn extension_decimal_u64(&self, key: &str) -> Option<u64> {
        self.extension_str(key).and_then(|s| s.parse::<u64>().ok())
    }

    /// Read an extension member as an array of strings (e.g. scope lists).
    #[must_use]
    pub fn extension_string_array(&self, key: &str) -> Vec<String> {
        match self.extensions.get(key) {
            Some(serde_json::Value::Array(items)) => items
                .iter()
                .filter_map(|v| match v {
                    serde_json::Value::String(s) => Some(s.clone()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Typed error catalogue
// ---------------------------------------------------------------------------

/// The discriminated kind of a [`Label309HttpError`], keyed on the RFC 7807
/// `code`.
///
/// Each variant carries only the code-specific projected fields; the shared
/// `problem` document, `request_id`, and `retry_after_seconds` live on the
/// owning [`Label309HttpError`] so they are not duplicated per variant. An
/// unrecognised code becomes [`HttpErrorKind::Other`], keeping the verbatim
/// document available so a newer gateway never breaks an older client.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HttpErrorKind {
    /// 401 — caller is not authenticated.
    Unauthorized,
    /// 403 — authenticated but lacks permission (`forbidden` / `csrf-invalid`).
    Forbidden,
    /// 403 — the key authenticated but lacks the required scope.
    InsufficientScope {
        /// The scopes the endpoint requires.
        required_scopes: Vec<String>,
        /// The scopes the key was granted.
        granted_scopes: Vec<String>,
    },
    /// 402 — the account balance is below the operation cost.
    InsufficientFunds {
        /// Current balance in USD micro-cents (decimal-string extension).
        balance_usd_micros: Option<u64>,
        /// Required amount in USD micro-cents (decimal-string extension).
        required_usd_micros: Option<u64>,
        /// Billing top-up URL.
        top_up_url: Option<String>,
    },
    /// 410 — the publish quote exceeded its TTL before `/publish` consumed it.
    QuoteExpired {
        /// The expired quote id.
        quote_id: Option<String>,
    },
    /// 404 — the supplied `quote_id` does not exist for the account.
    QuoteNotFound {
        /// The unknown quote id.
        quote_id: Option<String>,
    },
    /// 409 — the publish quote was already used by a prior `/publish` call.
    QuoteAlreadyConsumed {
        /// The already-consumed quote id.
        quote_id: Option<String>,
    },
    /// 404 — generic missing-resource response.
    NotFound,
    /// 404 — no Label 309 record is registered for the requested tx hash.
    RecordNotFound,
    /// 409 — the `Idempotency-Key` was reused with a different body.
    IdempotencyConflict,
    /// 429 — the per-key request quota was exceeded.
    RateLimited,
    /// 422 — the body parsed but failed schema validation; see `problem.errors`.
    ValidationFailed,
    /// 400 — the request body was structurally malformed.
    InvalidBody,
    /// 400 — `record` could not be parsed as canonical CBOR.
    MalformedCbor,
    /// 400 — the publish-batch `records[]` exceeded the per-call ceiling.
    BatchTooLarge {
        /// The maximum allowed batch size, when present.
        max: Option<u64>,
        /// The submitted batch size, when present.
        got: Option<u64>,
    },
    /// 400 — the publish-batch `records[]` array was empty.
    BatchEmpty,
    /// 500 — an unexpected server-side failure.
    InternalServer,
    /// 503 — temporary inability to serve the request.
    ServiceUnavailable,
    /// Any code the client does not recognise: the verbatim problem document.
    Other,
}

/// A typed HTTP error the client raises for any non-2xx response.
///
/// The error carries the verbatim [`ProblemDetails`], the correlation
/// `request_id` (the `X-Request-Id` header, falling back to the in-body
/// `trace_id`), the `Retry-After` header (when present), and the discriminated
/// [`HttpErrorKind`] with the code-specific projected fields. Dispatch on
/// [`code`](Self::code), [`http_status`](Self::http_status), or `matches!` on
/// [`kind`](Self::kind).
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("{}", .problem.message())]
pub struct Label309HttpError {
    /// The verbatim RFC 7807 problem document.
    pub problem: ProblemDetails,
    /// `X-Request-Id` header, or the in-body `trace_id` fallback.
    pub request_id: String,
    /// `Retry-After` header (seconds), when present.
    pub retry_after_seconds: Option<u64>,
    /// The discriminated, code-specific projection.
    pub kind: HttpErrorKind,
}

impl Label309HttpError {
    /// The RFC 7807 problem document carried by this error.
    #[must_use]
    pub fn problem(&self) -> &ProblemDetails {
        &self.problem
    }

    /// The lowercase-kebab problem `code`.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.problem.code
    }

    /// The HTTP status carried by the problem document.
    #[must_use]
    pub fn http_status(&self) -> u16 {
        self.problem.status
    }

    /// The correlation id: `X-Request-Id`, falling back to the in-body
    /// `trace_id`.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// The `Retry-After` header (seconds), when present.
    #[must_use]
    pub fn retry_after_seconds(&self) -> Option<u64> {
        self.retry_after_seconds
    }

    /// The discriminated, code-specific projection.
    #[must_use]
    pub fn kind(&self) -> &HttpErrorKind {
        &self.kind
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// The raw inputs a response yields for error parsing.
#[derive(Debug, Clone)]
pub struct ParseHttpErrorArgs {
    /// HTTP status code.
    pub http_status: u16,
    /// The decoded JSON response body, when present.
    pub body: Option<serde_json::Value>,
    /// `X-Request-Id` header, when present.
    pub request_id: Option<String>,
    /// `Retry-After` header parsed as integer seconds, when present.
    pub retry_after_seconds: Option<u64>,
}

/// Build the [`ProblemDetails`] for a non-conforming or missing body.
fn synthesise_problem(http_status: u16, request_id: Option<&str>) -> ProblemDetails {
    ProblemDetails {
        r#type: "about:blank".to_string(),
        title: format!("HTTP {http_status}"),
        status: http_status,
        detail: format!("Server returned HTTP {http_status} without a problem+json body."),
        code: format!("http-{http_status}"),
        trace_id: request_id.unwrap_or_default().to_string(),
        errors: None,
        instance: None,
        extensions: serde_json::Map::new(),
    }
}

/// Project the RFC 7807 `errors` member into typed entries.
///
/// Returns `None` only when the value is not an array. When it is an array each
/// element is taken element-by-element: non-object entries are skipped, and each
/// missing or non-string field defaults to `""`. A single malformed element thus
/// never discards the whole array (a lenient projection matching the reference).
fn project_problem_errors(value: &serde_json::Value) -> Option<Vec<ProblemErrorEntry>> {
    let arr = value.as_array()?;
    let entries = arr
        .iter()
        .filter_map(serde_json::Value::as_object)
        .map(|obj| {
            let field = |key: &str| {
                obj.get(key)
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            };
            ProblemErrorEntry {
                field: field("field"),
                code: field("code"),
                detail: field("detail"),
            }
        })
        .collect();
    Some(entries)
}

/// Lower a JSON body into a [`ProblemDetails`].
///
/// A body is "conforming" when it carries `code` or `title`; otherwise a minimal
/// problem is synthesised so the caller always sees a well-formed document.
fn to_problem_details(
    http_status: u16,
    body: Option<&serde_json::Value>,
    request_id: Option<&str>,
) -> ProblemDetails {
    let obj = match body {
        Some(serde_json::Value::Object(map)) => map,
        _ => return synthesise_problem(http_status, request_id),
    };

    let code = obj.get("code").and_then(serde_json::Value::as_str);
    let title = obj.get("title").and_then(serde_json::Value::as_str);
    if code.is_none() && title.is_none() {
        return synthesise_problem(http_status, request_id);
    }

    let status = obj
        .get("status")
        .and_then(serde_json::Value::as_u64)
        // Clamp rather than wrap: an out-of-range `status` (e.g. 99999) must not
        // narrow modulo 2^16 into a misleadingly small HTTP status.
        .map_or(http_status, |s| u16::try_from(s).unwrap_or(u16::MAX));
    let code = code.map_or_else(|| format!("http-{status}"), str::to_string);
    let r#type = obj
        .get("type")
        .and_then(serde_json::Value::as_str)
        .map_or_else(|| "about:blank".to_string(), str::to_string);
    let title = title.map_or_else(|| format!("HTTP {status}"), str::to_string);
    let detail = obj
        .get("detail")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    let trace_id = obj
        .get("trace_id")
        .and_then(serde_json::Value::as_str)
        .or(request_id)
        .unwrap_or_default()
        .to_string();
    let instance = obj
        .get("instance")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let errors = obj.get("errors").and_then(project_problem_errors);

    let mut extensions = serde_json::Map::new();
    for (key, value) in obj {
        if !CANONICAL_PROBLEM_KEYS.contains(&key.as_str()) {
            extensions.insert(key.clone(), value.clone());
        }
    }

    ProblemDetails {
        r#type,
        title,
        status,
        detail,
        code,
        trace_id,
        errors,
        instance,
        extensions,
    }
}

/// Decode an RFC 7807 response into the most-specific [`Label309HttpError`]
/// variant.
///
/// Dispatch is on the problem `code` (mapping `forbidden` + `csrf-invalid` to
/// [`HttpErrorKind::Forbidden`]); an unrecognised code falls through to
/// [`HttpErrorKind::Other`] with the verbatim document.
#[must_use]
pub fn parse_http_error(args: ParseHttpErrorArgs) -> Label309HttpError {
    let problem = to_problem_details(
        args.http_status,
        args.body.as_ref(),
        args.request_id.as_deref(),
    );
    // X-Request-Id falls back to the in-body trace_id so callers always have a
    // correlation handle even when a proxy strips the header.
    let request_id = args
        .request_id
        .clone()
        .unwrap_or_else(|| problem.trace_id.clone());
    let retry_after_seconds = args.retry_after_seconds;

    let kind = match problem.code.as_str() {
        "unauthorized" => HttpErrorKind::Unauthorized,
        "forbidden" | "csrf-invalid" => HttpErrorKind::Forbidden,
        "insufficient-scope" => HttpErrorKind::InsufficientScope {
            required_scopes: problem.extension_string_array("required"),
            granted_scopes: problem.extension_string_array("granted"),
        },
        "insufficient-funds" => HttpErrorKind::InsufficientFunds {
            balance_usd_micros: problem.extension_decimal_u64("balance_usd_micros"),
            required_usd_micros: problem.extension_decimal_u64("required_usd_micros"),
            top_up_url: problem.extension_str("top_up_url"),
        },
        "quote-expired" => HttpErrorKind::QuoteExpired {
            quote_id: problem.extension_str("quote_id"),
        },
        "quote-not-found" => HttpErrorKind::QuoteNotFound {
            quote_id: problem.extension_str("quote_id"),
        },
        "quote-already-consumed" => HttpErrorKind::QuoteAlreadyConsumed {
            quote_id: problem.extension_str("quote_id"),
        },
        "not-found" => HttpErrorKind::NotFound,
        "record-not-found" => HttpErrorKind::RecordNotFound,
        "idempotency-key-conflict" => HttpErrorKind::IdempotencyConflict,
        "rate-limited" => HttpErrorKind::RateLimited,
        "validation-failed" => HttpErrorKind::ValidationFailed,
        "invalid-body" => HttpErrorKind::InvalidBody,
        "malformed-cbor" => HttpErrorKind::MalformedCbor,
        "batch-too-large" => HttpErrorKind::BatchTooLarge {
            max: problem.extension_u64("max"),
            got: problem.extension_u64("got"),
        },
        "batch-empty" => HttpErrorKind::BatchEmpty,
        "internal-error" => HttpErrorKind::InternalServer,
        // A gateway that prices on a live FX oracle may surface a transient
        // `fx-stale` pricing outage; to a vendor-neutral client that is just a
        // temporary inability to serve, i.e. a service-unavailable condition.
        "service-unavailable" | "fx-stale" => HttpErrorKind::ServiceUnavailable,
        _ => HttpErrorKind::Other,
    };

    Label309HttpError {
        problem,
        request_id,
        retry_after_seconds,
        kind,
    }
}
