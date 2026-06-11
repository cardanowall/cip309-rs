//! Canonical outbound HTTP egress with SSRF hardening.
//!
//! This is the verifier's single egress point. Every outbound request flows
//! through [`wrap_fetch_outbound`], which applies — in order — a `webhook`-purpose
//! guard, a protocol allowlist (`http`/`https`), a method allowlist (`GET`/`POST`),
//! a deny-host short circuit, a bounded response-body cap, a bounded timeout, and
//! optional retry with jittered exponential backoff. Each call appends one
//! [`HttpCallRecord`] to a caller-owned audit trail.
//!
//! Two distinct hazard models are handled here:
//!
//! 1. **Service independence** — [`matches_deny_list`] is a hostname-pattern
//!    matcher. A verifier rejects the operator's own host and loopback so a
//!    record can never appear to "verify" merely because the verifier reached the
//!    publisher's server. This is a policy guard, not an IP guard.
//!
//! 2. **SSRF** — [`assert_webhook_url_safe`] operates at the IP layer for
//!    user-supplied URLs. It resolves the hostname (A + AAAA) through an
//!    injectable resolver, range-checks every resolved address against the
//!    canonical blocklist ([`BLOCKED_IPV4_RANGES`] / [`BLOCKED_IPV6_RANGES`]), and
//!    returns the resolved IP so the caller can pin the TCP connection to it —
//!    closing the DNS-rebinding check-time/use-time window. It cannot be bypassed
//!    by hostname tricks (`1.0.0.1.nip.io`) or by a resolver that hands back a
//!    private address for a public-looking name.
//!
//! # Determinism
//!
//! The pure logic — deny-host matching, IP classification, URL/protocol/method
//! validation, and size-cap enforcement — is separated from the network call so
//! it is unit-testable without I/O. The retry loop never reads the system clock
//! or a real RNG: a [`Clock`] and a [`Jitter`] are injected so backoff timing is
//! deterministic in tests.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

#[cfg(feature = "client")]
use reqwest::dns::{Addrs, Resolve, Resolving};
#[cfg(feature = "client")]
use std::sync::Arc;

/// Canonical deny-host list a service-independent verifier rejects so a record
/// can never be made to "verify" only because it reached a loopback address.
///
/// The wrapper accepts arbitrary lists; this canonical set is exported so
/// callers do not duplicate it inline. Deployments add their own operator
/// hosts on top — the service-independence hazard is any host the verifying
/// party itself controls, which only the deployment can name.
pub const DENY_HOSTS_DEFAULT: [&str; 2] = ["localhost", "127.0.0.1"];

/// Default per-request timeout for an outbound gateway fetch.
pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;

/// Default response-body cap for the verifier's gateway fetches: 64 MiB.
///
/// 64 MiB sits well above any single sealed-PoE ciphertext or merkle-leaf payload
/// a verifier would realistically recompute a hash over, while bounding the memory
/// a hostile gateway can force the verifier to allocate for one request. Callers
/// that legitimately handle larger content raise it per call via
/// [`FetchOutboundOptions::max_bytes`].
pub const DEFAULT_OUTBOUND_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// HTTP statuses that are retried when retries are enabled.
pub const DEFAULT_RETRYABLE_STATUSES: [u16; 3] = [502, 503, 504];

/// Backoff base, in milliseconds, indexed by attempt number (0-based, clamped).
const BACKOFF_BASE_MS: [u64; 3] = [1000, 2000, 4000];

/// Maximum proportional jitter applied to a backoff delay (±25%).
const JITTER_RATIO: f64 = 0.25;

// ---------------------------------------------------------------------------
// Purpose / method
// ---------------------------------------------------------------------------

/// The closed set of purposes an outbound call may carry.
///
/// `cardano`, `arweave`, and `ipfs` are the three v1 gateway-chain purposes.
/// `https` is a transitional tag for non-storage HTTPS auxiliaries. `webhook`
/// is the user-supplied-URL purpose: it triggers the SSRF guard
/// ([`assert_webhook_url_safe`]) and is refused by [`wrap_fetch_outbound`], which
/// forces such calls down the hardened webhook path instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpPurpose {
    /// Cardano gateway traffic (tx CBOR, tx info, chain tip).
    Cardano,
    /// Arweave gateway traffic (`ar://` content retrieval).
    Arweave,
    /// IPFS gateway traffic (`ipfs://` content retrieval).
    Ipfs,
    /// Transitional tag for non-storage HTTPS auxiliaries.
    Https,
    /// User-supplied URL: routes through the SSRF guard, never the generic wrap.
    Webhook,
}

impl HttpPurpose {
    /// The stable wire token for this purpose, identical across the SDKs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            HttpPurpose::Cardano => "cardano",
            HttpPurpose::Arweave => "arweave",
            HttpPurpose::Ipfs => "ipfs",
            HttpPurpose::Https => "https",
            HttpPurpose::Webhook => "webhook",
        }
    }
}

/// The closed set of HTTP methods the egress allows.
///
/// `PUT` is admitted because the gateway's resumable-upload protocol uploads each
/// chunk with an idempotent positional `PUT`; it carries the same deny-host /
/// SSRF / protocol pre-flight every other method does, so the security boundary
/// is unchanged. `DELETE`, `PATCH`, and the rest remain unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    /// HTTP `GET`.
    Get,
    /// HTTP `POST`.
    Post,
    /// HTTP `PUT` (idempotent positional chunk upload).
    Put,
}

impl HttpMethod {
    /// The stable wire token for this method.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
        }
    }
}

// ---------------------------------------------------------------------------
// Options / result / audit
// ---------------------------------------------------------------------------

/// Per-call options for an outbound fetch.
#[derive(Debug, Clone)]
pub struct FetchOutboundOptions {
    /// HTTP method (only `GET` / `POST` are allowed).
    pub method: HttpMethod,
    /// Purpose tag, recorded on the audit trail and used to route `webhook`.
    pub purpose: HttpPurpose,
    /// Optional request headers.
    pub headers: Vec<(String, String)>,
    /// Optional request body (used for `POST`).
    pub body: Option<String>,
    /// Hard cap on the response body the primitive buffers. Defaults to
    /// [`DEFAULT_OUTBOUND_MAX_BYTES`] when `None`.
    pub max_bytes: Option<u64>,
}

impl FetchOutboundOptions {
    /// Construct options with the given method and purpose and no headers/body.
    #[must_use]
    pub fn new(method: HttpMethod, purpose: HttpPurpose) -> Self {
        Self {
            method,
            purpose,
            headers: Vec::new(),
            body: None,
            max_bytes: None,
        }
    }
}

/// The outcome of one successful outbound fetch.
#[derive(Debug, Clone)]
pub struct FetchOutboundResult {
    /// HTTP status code.
    pub status: u16,
    /// Response body, already bounded by the size cap.
    pub bytes: Vec<u8>,
    /// Wall-clock duration of the fetch, in milliseconds.
    pub duration_ms: u64,
}

/// Audit-log entry for one outbound HTTP fetch.
///
/// Field names mirror the wire shape (the report's audit trail) so the record
/// can land there without a key-renaming pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpCallRecord {
    /// The requested URL.
    pub url: String,
    /// The method as recorded (a rejected pre-flight is recorded as `GET`).
    pub method: HttpMethod,
    /// The HTTP status when a response was received; `None` when none was
    /// (refused call, transport failure) — serialised as JSON null.
    pub status: Option<u16>,
    /// Number of body bytes received (`0` for a failed/rejected call).
    pub bytes: u64,
    /// Wall-clock duration, in milliseconds.
    pub duration_ms: u64,
    /// The call's purpose tag.
    pub purpose: HttpPurpose,
}

/// Retry / timeout configuration for [`wrap_fetch_outbound`].
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Number of retries after the first attempt. `0` means a single attempt.
    pub retries: u32,
    /// Statuses that trigger a retry when `retries > 0`.
    pub retryable_statuses: Vec<u16>,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            retries: 0,
            retryable_statuses: DEFAULT_RETRYABLE_STATUSES.to_vec(),
        }
    }
}

/// Full configuration for [`wrap_fetch_outbound`].
#[derive(Debug, Clone, Default)]
pub struct WrapFetchOutboundConfig {
    /// Deny-host patterns. An empty list disables the deny-host short circuit.
    pub deny_hosts: Vec<String>,
    /// Retry / timeout configuration.
    pub retry: RetryConfig,
}

// ---------------------------------------------------------------------------
// Typed errors
// ---------------------------------------------------------------------------

/// The error type of an outbound fetch.
///
/// Variants reproduce the typed errors and stable `code` strings of the
/// reference SDKs. [`OutboundError::code`] yields the wire token.
#[derive(Debug, thiserror::Error)]
pub enum OutboundError {
    /// The target host is on the deny list (service-independence violation).
    #[error("SERVICE_INDEPENDENCE_VIOLATION: host \"{host}\" is in denyHosts (url={url})")]
    DenyHost {
        /// The canonicalised host that matched a deny entry.
        host: String,
        /// The rejected URL.
        url: String,
    },
    /// The URL scheme is not in the `{http, https}` allowlist.
    #[error("UNSUPPORTED_PROTOCOL: \"{protocol}\" not in {{http:, https:}} (url={url})")]
    UnsupportedProtocol {
        /// The offending scheme (with trailing colon), or empty if unparseable.
        protocol: String,
        /// The rejected URL.
        url: String,
    },
    /// The method is not in the `{GET, POST}` allowlist.
    #[error("UNSUPPORTED_METHOD: \"{method}\" not in {{GET, POST}} (url={url})")]
    UnsupportedMethod {
        /// The offending method.
        method: String,
        /// The rejected URL.
        url: String,
    },
    /// The response body exceeded the configured cap.
    #[error("OUTBOUND_BODY_TOO_LARGE: response exceeded {limit_bytes} bytes (url={url})")]
    BodyTooLarge {
        /// The rejected URL.
        url: String,
        /// The cap that was exceeded.
        limit_bytes: u64,
    },
    /// The `webhook` purpose was sent through the generic wrapper.
    #[error("webhook purpose must be sent via fetch_webhook, not fetch_outbound (url={url})")]
    WebhookPurposeRejected {
        /// The rejected URL.
        url: String,
    },
    /// Every attempt failed (retry mode terminal failure).
    #[error("OUTBOUND_EXHAUSTED: {attempts} attempts exhausted (url={url}, lastStatus={})",
        last_status.map_or_else(|| "-".to_string(), |s| s.to_string()))]
    Exhausted {
        /// The URL whose attempts were exhausted.
        url: String,
        /// Total number of attempts made.
        attempts: u32,
        /// The last observed status, if any.
        last_status: Option<u16>,
        /// The last transport error message, if any.
        last_error: Option<String>,
    },
    /// An underlying transport error (DNS, TLS, connection, body read).
    #[error("OUTBOUND_TRANSPORT: {message} (url={url})")]
    Transport {
        /// The URL that failed.
        url: String,
        /// The transport error description.
        message: String,
    },
}

impl OutboundError {
    /// The stable wire `code` for this error, identical across the SDKs.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            OutboundError::DenyHost { .. } => "SERVICE_INDEPENDENCE_VIOLATION",
            OutboundError::UnsupportedProtocol { .. } => "UNSUPPORTED_PROTOCOL",
            OutboundError::UnsupportedMethod { .. } => "UNSUPPORTED_METHOD",
            OutboundError::BodyTooLarge { .. } => "OUTBOUND_BODY_TOO_LARGE",
            OutboundError::WebhookPurposeRejected { .. } => "WEBHOOK_PURPOSE_REJECTED",
            OutboundError::Exhausted { .. } => "OUTBOUND_EXHAUSTED",
            OutboundError::Transport { .. } => "OUTBOUND_TRANSPORT",
        }
    }

    /// `true` for the pre-flight rejections that short circuit without retry.
    fn is_preflight(&self) -> bool {
        matches!(
            self,
            OutboundError::DenyHost { .. }
                | OutboundError::UnsupportedProtocol { .. }
                | OutboundError::UnsupportedMethod { .. }
                | OutboundError::WebhookPurposeRejected { .. }
        )
    }
}

// ---------------------------------------------------------------------------
// Deny-host matching (pure logic)
// ---------------------------------------------------------------------------

/// Canonicalise a host for deny-list comparison: strip IPv6 brackets and a
/// trailing dot, then lowercase.
fn canonicalise_host(host: &str) -> String {
    let mut h = host;
    h = h.strip_prefix('[').unwrap_or(h);
    h = h.strip_suffix(']').unwrap_or(h);
    h = h.strip_suffix('.').unwrap_or(h);
    h.to_lowercase()
}

/// `true` if `host` matches `127.x.x.x` (the full loopback `/8`).
fn is_loopback_127(host: &str) -> bool {
    let octets: Vec<&str> = host.split('.').collect();
    if octets.len() != 4 || octets[0] != "127" {
        return false;
    }
    octets
        .iter()
        .all(|o| !o.is_empty() && o.len() <= 3 && o.bytes().all(|b| b.is_ascii_digit()))
}

/// Match a hostname against a deny-list of patterns.
///
/// Patterns are matched after canonicalisation (bracket/trailing-dot strip,
/// lowercase). A `*.suffix` entry matches any host ending in `.suffix` (but not
/// the bare suffix). The special entries alias loopback indirection:
/// `localhost` also matches `::1`, `0.0.0.0`, and the cloud-metadata IP
/// `169.254.169.254`; `127.0.0.1` matches the entire `127.0.0.0/8` block.
#[must_use]
pub fn matches_deny_list<S: AsRef<str>>(host: &str, deny_hosts: &[S]) -> bool {
    let h = canonicalise_host(host);
    for raw in deny_hosts {
        let pattern = raw.as_ref().trim_end_matches('.').to_lowercase();
        if let Some(suffix) = pattern.strip_prefix("*.") {
            if h.ends_with(&format!(".{suffix}")) {
                return true;
            }
            continue;
        }
        if h == pattern {
            return true;
        }
        if pattern == "localhost" && (h == "::1" || h == "0.0.0.0" || h == "169.254.169.254") {
            return true;
        }
        if pattern == "127.0.0.1" && is_loopback_127(&h) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// URL parsing helpers (pure logic)
// ---------------------------------------------------------------------------

/// Extract the lowercase scheme (with trailing colon) from a URL string, or
/// `None` if the URL cannot be parsed.
fn parse_protocol(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    Some(format!("{}:", parsed.scheme().to_lowercase()))
}

/// Extract the hostname from a URL string, or `None` if it cannot be parsed.
fn parse_hostname(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    parsed.host_str().map(str::to_string)
}

/// `true` if the URL scheme is `http:` or `https:`.
fn is_allowed_protocol(url: &str) -> bool {
    matches!(
        parse_protocol(url).as_deref(),
        Some("http:") | Some("https:")
    )
}

// ---------------------------------------------------------------------------
// Injected clock + jitter (determinism)
// ---------------------------------------------------------------------------

/// Sleeps for a backoff delay. Injected so the retry loop never touches the real
/// system timer; tests substitute a recorder that captures requested delays.
pub trait Clock: Send + Sync {
    /// Block for `duration`.
    fn sleep(&self, duration: Duration);
}

/// The default clock: blocks the current thread.
#[derive(Debug, Clone, Copy, Default)]
pub struct ThreadSleepClock;

impl Clock for ThreadSleepClock {
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Supplies the jitter multiplier applied to a backoff base. Injected so backoff
/// timing is deterministic and testable without a real RNG.
///
/// The returned value `r` is used as `base_ms * r`. To reproduce the reference's
/// `±25%` band, an implementation returns `1 + (rand - 0.5) * 2 * 0.25` for a
/// `rand` in `[0, 1)`.
pub trait Jitter: Send + Sync {
    /// The multiplier for `attempt_index` (0-based).
    fn multiplier(&self, attempt_index: usize) -> f64;
}

/// The default jitter source, backed by the OS CSPRNG. Produces a multiplier in
/// `[1 - JITTER_RATIO, 1 + JITTER_RATIO]`.
#[derive(Debug, Clone, Copy, Default)]
pub struct RandomJitter;

impl Jitter for RandomJitter {
    fn multiplier(&self, _attempt_index: usize) -> f64 {
        let mut buf = [0u8; 8];
        // The OS CSPRNG. A failure here is unrecoverable for backoff timing, so a
        // mid-band fallback keeps the retry loop running rather than panicking.
        let rand = match getrandom::getrandom(&mut buf) {
            Ok(()) => (u64::from_le_bytes(buf) as f64) / (u64::MAX as f64),
            Err(_) => 0.5,
        };
        1.0 + (rand - 0.5) * 2.0 * JITTER_RATIO
    }
}

/// Compute the jittered backoff delay for a given attempt, in milliseconds.
fn backoff_jittered_ms(attempt_index: usize, jitter: &dyn Jitter) -> f64 {
    let idx = attempt_index.min(BACKOFF_BASE_MS.len() - 1);
    let base = BACKOFF_BASE_MS[idx] as f64;
    base * jitter.multiplier(attempt_index)
}

// ---------------------------------------------------------------------------
// fetch-outbound primitive
// ---------------------------------------------------------------------------

/// A network transport: performs one fetch and returns the bounded result.
///
/// The production implementation, `ReqwestTransport`, ships behind the `client`
/// feature; with that feature off a caller supplies its own implementation.
/// Tests inject a stub so the wrapper's pure control flow (allowlists,
/// deny-host, retry, audit) is exercised without real I/O.
pub trait FetchTransport: Send + Sync {
    /// Perform one fetch. The size cap in `opts.max_bytes` must be honoured.
    fn fetch(
        &self,
        url: &str,
        opts: &FetchOutboundOptions,
    ) -> Result<FetchOutboundResult, OutboundError>;
}

/// Apply the egress policy around a transport: webhook refusal, protocol and
/// method allowlists, deny-host short circuit, retry with jittered backoff, and
/// the audit trail.
///
/// Pre-flight rejections (deny-host, protocol, method, webhook) record a single
/// audit row with a null `status` and a `GET` method, then return immediately.
/// On each transport invocation one audit row is appended. With `retries == 0`
/// the terminal transport error is returned verbatim; with `retries > 0` it is
/// wrapped in [`OutboundError::Exhausted`].
#[allow(clippy::too_many_arguments)]
pub fn wrap_fetch_outbound(
    transport: &dyn FetchTransport,
    audit: &mut Vec<HttpCallRecord>,
    config: &WrapFetchOutboundConfig,
    clock: &dyn Clock,
    jitter: &dyn Jitter,
    url: &str,
    opts: &FetchOutboundOptions,
) -> Result<FetchOutboundResult, OutboundError> {
    // The webhook purpose has bespoke requirements (DNS pinning, per-hop redirect
    // re-checking) the generic wrapper cannot satisfy; force the hardened path.
    if opts.purpose == HttpPurpose::Webhook {
        audit.push(preflight_row(url, HttpPurpose::Webhook));
        return Err(OutboundError::WebhookPurposeRejected {
            url: url.to_string(),
        });
    }

    // Protocol allowlist.
    if !is_allowed_protocol(url) {
        audit.push(preflight_row(url, opts.purpose));
        let protocol = parse_protocol(url).unwrap_or_default();
        return Err(OutboundError::UnsupportedProtocol {
            protocol,
            url: url.to_string(),
        });
    }

    // Method allowlist is enforced by the `HttpMethod` type: only Get/Post exist.
    // The string-method rejection path is exercised through `fetch_outbound_method`.

    // Deny-host short circuit.
    if !config.deny_hosts.is_empty() {
        let host = parse_hostname(url).unwrap_or_default();
        if matches_deny_list(&host, &config.deny_hosts) {
            audit.push(HttpCallRecord {
                url: url.to_string(),
                method: opts.method,
                status: None,
                bytes: 0,
                duration_ms: 0,
                purpose: opts.purpose,
            });
            return Err(OutboundError::DenyHost {
                host: canonicalise_host(&host),
                url: url.to_string(),
            });
        }
    }

    // Retry loop. retries == 0 → single attempt.
    let retries = config.retry.retries;
    let total_attempts = retries + 1;
    let mut last_status: Option<u16> = None;
    let mut last_error: Option<OutboundError> = None;

    for attempt in 1..=total_attempts {
        match transport.fetch(url, opts) {
            Ok(result) => {
                audit.push(HttpCallRecord {
                    url: url.to_string(),
                    method: opts.method,
                    status: Some(result.status),
                    bytes: result.bytes.len() as u64,
                    duration_ms: result.duration_ms,
                    purpose: opts.purpose,
                });
                if config.retry.retryable_statuses.contains(&result.status) && retries > 0 {
                    last_status = Some(result.status);
                    if attempt < total_attempts {
                        sleep_backoff(clock, jitter, attempt);
                        continue;
                    }
                    break;
                }
                return Ok(result);
            }
            Err(e) if e.is_preflight() => {
                // A transport that surfaces a pre-flight-class error is recorded
                // and re-thrown without retry, matching the reference.
                audit.push(preflight_row(url, opts.purpose));
                return Err(e);
            }
            Err(e) => {
                audit.push(HttpCallRecord {
                    url: url.to_string(),
                    method: opts.method,
                    status: None,
                    bytes: 0,
                    duration_ms: 0,
                    purpose: opts.purpose,
                });
                last_error = Some(e);
                if attempt < total_attempts {
                    sleep_backoff(clock, jitter, attempt);
                    continue;
                }
                break;
            }
        }
    }

    // Single-attempt mode returns the original error verbatim; retry mode wraps
    // the terminal failure in Exhausted.
    if retries == 0 {
        if let Some(e) = last_error {
            return Err(e);
        }
    }
    Err(OutboundError::Exhausted {
        url: url.to_string(),
        attempts: total_attempts,
        last_status,
        last_error: last_error.map(|e| e.to_string()),
    })
}

/// The audit row recorded for a pre-flight rejection: `GET`, null status,
/// zero counters.
fn preflight_row(url: &str, purpose: HttpPurpose) -> HttpCallRecord {
    HttpCallRecord {
        url: url.to_string(),
        method: HttpMethod::Get,
        status: None,
        bytes: 0,
        duration_ms: 0,
        purpose,
    }
}

/// Sleep for the jittered backoff delay before the given attempt.
fn sleep_backoff(clock: &dyn Clock, jitter: &dyn Jitter, attempt: u32) {
    let ms = backoff_jittered_ms((attempt - 1) as usize, jitter);
    clock.sleep(Duration::from_secs_f64(ms.max(0.0) / 1000.0));
}

/// Validate a string method against the `{GET, POST}` allowlist, mapping to
/// [`HttpMethod`] or rejecting with [`OutboundError::UnsupportedMethod`].
///
/// The strongly-typed [`HttpMethod`] makes illegal methods unrepresentable on the
/// primary path; this entry point exists for callers that receive a raw method
/// string (e.g. an adapter over an arbitrary request) so the rejection surfaces
/// the same typed error and code as the reference.
pub fn parse_http_method(method: &str, url: &str) -> Result<HttpMethod, OutboundError> {
    match method {
        "GET" => Ok(HttpMethod::Get),
        "POST" => Ok(HttpMethod::Post),
        "PUT" => Ok(HttpMethod::Put),
        other => Err(OutboundError::UnsupportedMethod {
            method: other.to_string(),
            url: url.to_string(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Reqwest blocking transport with DNS pinning
// ---------------------------------------------------------------------------

/// A fixed-resolution DNS resolver that pins a hostname to one socket address.
///
/// Wired into the reqwest client so the TCP connection targets the IP the SSRF
/// guard already range-checked, closing the DNS-rebinding window. The original
/// hostname still drives the `Host:` header, TLS SNI, and certificate
/// verification.
#[cfg(feature = "client")]
struct PinnedResolver {
    host: String,
    addr: std::net::IpAddr,
}

#[cfg(feature = "client")]
impl Resolve for PinnedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> Resolving {
        let want = self.host.to_lowercase();
        let got = name.as_str().to_lowercase();
        let addr = self.addr;
        Box::pin(async move {
            if got == want {
                let socket = std::net::SocketAddr::new(addr, 0);
                let iter: Addrs = Box::new(std::iter::once(socket));
                Ok(iter)
            } else {
                // Any other name is refused: the client must never resolve a host
                // we did not pin (e.g. after an un-rechecked redirect).
                Err(format!("PinnedResolver: refused to resolve unexpected host {got}").into())
            }
        })
    }
}

/// The production transport: a blocking reqwest client that streams the response
/// body and enforces the size cap without trusting `Content-Length`.
///
/// When `pinned` is set, the client resolves the pinned hostname to the supplied
/// IP and refuses every other name — the DNS-rebinding mitigation for the webhook
/// path. The generic gateway path leaves `pinned` unset and uses the system
/// resolver.
#[cfg(feature = "client")]
#[derive(Default)]
pub struct ReqwestTransport {
    pinned: Option<(String, std::net::IpAddr)>,
}

#[cfg(feature = "client")]
impl ReqwestTransport {
    /// A transport using the system DNS resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A transport that pins `hostname` to `addr` for the TCP connection.
    ///
    /// Use after [`assert_webhook_url_safe`] has validated the resolved IP: the
    /// connection then targets exactly that address, and any attempt to resolve a
    /// different host (an un-rechecked redirect) is refused.
    #[must_use]
    pub fn pinned(hostname: impl Into<String>, addr: std::net::IpAddr) -> Self {
        Self {
            pinned: Some((hostname.into(), addr)),
        }
    }

    fn build_client(&self) -> Result<reqwest::blocking::Client, OutboundError> {
        // Never follow redirects. The SSRF guard validates only the original URL;
        // a hostile gateway returning `302 Location: http://169.254.169.254/…`
        // would otherwise pivot the fetch into the internal network behind the
        // verifier's back. A 3xx surfaces as a non-200 status instead.
        let mut builder = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(DEFAULT_TIMEOUT_MS))
            .redirect(reqwest::redirect::Policy::none());
        if let Some((host, addr)) = &self.pinned {
            builder = builder
                .dns_resolver(Arc::new(PinnedResolver {
                    host: host.clone(),
                    addr: *addr,
                }))
                // Pinned mode is the user-supplied-URL (webhook) path: the
                // connection must target the IP the SSRF guard validated. reqwest
                // honours HTTP_PROXY/HTTPS_PROXY/ALL_PROXY from the environment by
                // default, which would route the request through a proxy and
                // around the pin — the proxy could then reach a private host the
                // range-block thought it had excluded. Clearing proxy inheritance
                // keeps the socket pointed at the validated address. The generic
                // (unpinned) path leaves proxy support intact for chain fetches.
                .no_proxy();
        }
        builder.build().map_err(|e| OutboundError::Transport {
            url: String::new(),
            message: e.to_string(),
        })
    }
}

#[cfg(feature = "client")]
impl FetchTransport for ReqwestTransport {
    fn fetch(
        &self,
        url: &str,
        opts: &FetchOutboundOptions,
    ) -> Result<FetchOutboundResult, OutboundError> {
        let started = std::time::Instant::now();
        let max_bytes = opts.max_bytes.unwrap_or(DEFAULT_OUTBOUND_MAX_BYTES);
        let client = self.build_client()?;

        let method = match opts.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
        };
        let mut req = client.request(method, url);
        for (k, v) in &opts.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(body) = &opts.body {
            req = req.body(body.clone());
        }

        let mut resp = req.send().map_err(|e| OutboundError::Transport {
            url: url.to_string(),
            message: e.to_string(),
        })?;
        let status = resp.status().as_u16();

        // Fast path: a truthful Content-Length over the cap lets us bail before
        // reading a body byte. A lying/absent header is still caught by the
        // streaming counter below — the header is an optimisation, not the guard.
        if let Some(len) = resp.content_length() {
            if len > max_bytes {
                return Err(OutboundError::BodyTooLarge {
                    url: url.to_string(),
                    limit_bytes: max_bytes,
                });
            }
        }

        let bytes = read_body_capped(&mut resp, url, max_bytes)?;
        Ok(FetchOutboundResult {
            status,
            bytes,
            duration_ms: started.elapsed().as_millis() as u64,
        })
    }
}

/// Stream the response body, stopping the instant the running byte count exceeds
/// `max_bytes`. This is the real OOM guard: a gateway that withholds or lies about
/// `Content-Length` still cannot make us buffer more than the cap.
#[cfg(feature = "client")]
fn read_body_capped(
    resp: &mut reqwest::blocking::Response,
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

/// High-level outbound fetch: compose the default transport with the wrapper.
///
/// Records one audit row on success (or a pre-flight row on rejection) and uses
/// the production clock and jitter sources.
#[cfg(feature = "client")]
pub fn fetch_outbound(
    url: &str,
    opts: &FetchOutboundOptions,
    audit: &mut Vec<HttpCallRecord>,
    config: &WrapFetchOutboundConfig,
) -> Result<FetchOutboundResult, OutboundError> {
    let transport = ReqwestTransport::new();
    wrap_fetch_outbound(
        &transport,
        audit,
        config,
        &ThreadSleepClock,
        &RandomJitter,
        url,
        opts,
    )
}

// ===========================================================================
// SSRF guard — assert_webhook_url_safe + IP blocklist
// ===========================================================================

/// The discriminated reason a webhook URL was judged unsafe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookUrlUnsafeReason {
    /// The URL could not be parsed.
    InvalidUrl,
    /// The scheme is not `https:` (or `http:` under the test escape hatch).
    UnsupportedProtocol,
    /// DNS resolution of the hostname failed.
    DnsResolutionFailed,
    /// A resolved IP fell inside a blocked range.
    BlockedIpRange,
    /// DNS resolution returned no records.
    NoDnsRecords,
}

impl WebhookUrlUnsafeReason {
    /// The stable wire token for this reason, identical across the SDKs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            WebhookUrlUnsafeReason::InvalidUrl => "invalid-url",
            WebhookUrlUnsafeReason::UnsupportedProtocol => "unsupported-protocol",
            WebhookUrlUnsafeReason::DnsResolutionFailed => "dns-resolution-failed",
            WebhookUrlUnsafeReason::BlockedIpRange => "blocked-ip-range",
            WebhookUrlUnsafeReason::NoDnsRecords => "no-dns-records",
        }
    }
}

/// A webhook URL was judged unsafe for outbound delivery.
#[derive(Debug, thiserror::Error)]
#[error("WEBHOOK_URL_UNSAFE: {reason} (url={url}, hostname={hostname}{})",
    resolved_ip.as_ref().map_or_else(String::new, |ip| format!(", ip={ip}")))]
pub struct WebhookUrlUnsafeError {
    /// The discriminated cause.
    pub reason: WebhookUrlUnsafeReason,
    /// The offending URL.
    pub url: String,
    /// The parsed hostname (empty for an unparseable URL).
    pub hostname: String,
    /// The resolved IP, when the failure is a blocked range.
    pub resolved_ip: Option<String>,
}

impl std::fmt::Display for WebhookUrlUnsafeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl WebhookUrlUnsafeError {
    /// The stable wire `code` for this error.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        "WEBHOOK_URL_UNSAFE"
    }
}

/// One resolved DNS record: an address and its IP family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedRecord {
    /// The resolved IP address.
    pub address: std::net::IpAddr,
    /// The IP family (`4` or `6`).
    pub family: u8,
}

/// A DNS resolver for the SSRF guard. Injected so tests supply deterministic
/// A/AAAA records; the default ([`SystemResolver`]) consults the OS resolver.
pub trait ResolveHost: Send + Sync {
    /// Resolve `hostname` to its A and AAAA records, or return an error string on
    /// resolution failure.
    fn resolve(&self, hostname: &str) -> Result<Vec<ResolvedRecord>, String>;
}

/// The default resolver: the standard library's blocking name resolution.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl ResolveHost for SystemResolver {
    fn resolve(&self, hostname: &str) -> Result<Vec<ResolvedRecord>, String> {
        use std::net::ToSocketAddrs;
        // Port 0 is a placeholder; only the addresses matter here.
        let addrs = (hostname, 0u16)
            .to_socket_addrs()
            .map_err(|e| e.to_string())?;
        Ok(addrs
            .map(|sa| {
                let ip = sa.ip();
                let family = if ip.is_ipv4() { 4 } else { 6 };
                ResolvedRecord {
                    address: ip,
                    family,
                }
            })
            .collect())
    }
}

/// Options for [`assert_webhook_url_safe`].
#[derive(Default)]
pub struct AssertWebhookUrlSafeOptions<'a> {
    /// Loosen the guard so it accepts `http://` and private/loopback IPs. NEVER
    /// enable in production; tests use it to exercise the pinned-connection path
    /// against a local listener.
    pub allow_private_for_tests: bool,
    /// Injectable resolver. Defaults to [`SystemResolver`] when `None`.
    pub resolve_host: Option<&'a dyn ResolveHost>,
}

/// The successful outcome of the SSRF guard.
#[derive(Debug, Clone)]
pub struct AssertWebhookUrlSafeResult {
    /// The first resolved IP — the caller pins the TCP socket to this address.
    pub resolved_ip: std::net::IpAddr,
    /// The IP family (`4` or `6`) of the resolved IP.
    pub family: u8,
    /// The original hostname, preserved for the `Host:` header and TLS SNI.
    pub hostname: String,
}

/// `true` if a host string is a bare IP literal (so DNS is skipped).
fn looks_like_ip_literal(host: &str) -> bool {
    host.parse::<Ipv4Addr>().is_ok() || host.contains(':')
}

/// Assert `url` is safe for outbound webhook delivery.
///
/// On success returns the resolved IP and family; the caller is REQUIRED to pin
/// the TCP connection to that IP (the `client`-feature `ReqwestTransport::pinned`
/// constructor does this) so a DNS-rebind between check time and use time cannot
/// redirect the request to a private address. The guard is HTTPS-only by
/// default; resolves A + AAAA; rejects the whole check if ANY resolved address
/// is in a blocked range.
pub fn assert_webhook_url_safe(
    url: &str,
    opts: &AssertWebhookUrlSafeOptions<'_>,
) -> Result<AssertWebhookUrlSafeResult, WebhookUrlUnsafeError> {
    let allow_private = opts.allow_private_for_tests;

    let parsed = url::Url::parse(url).map_err(|_| WebhookUrlUnsafeError {
        reason: WebhookUrlUnsafeReason::InvalidUrl,
        url: url.to_string(),
        hostname: String::new(),
        resolved_ip: None,
    })?;

    let scheme = parsed.scheme();
    if scheme != "https" && !(allow_private && scheme == "http") {
        return Err(WebhookUrlUnsafeError {
            reason: WebhookUrlUnsafeReason::UnsupportedProtocol,
            url: url.to_string(),
            hostname: parsed.host_str().unwrap_or("").to_string(),
            resolved_ip: None,
        });
    }

    // A URL whose host cannot be a network host (e.g. data:, file:) has no
    // host_str; treat it as an unparseable target.
    let raw_host = parsed.host_str().ok_or_else(|| WebhookUrlUnsafeError {
        reason: WebhookUrlUnsafeReason::InvalidUrl,
        url: url.to_string(),
        hostname: String::new(),
        resolved_ip: None,
    })?;
    let hostname = canonicalise_host(raw_host);

    let records: Vec<ResolvedRecord> = if looks_like_ip_literal(&hostname) {
        let address: std::net::IpAddr = hostname.parse().map_err(|_| WebhookUrlUnsafeError {
            // A bracketed/odd literal that fails to parse is treated as an
            // unresolvable target rather than silently allowed.
            reason: WebhookUrlUnsafeReason::DnsResolutionFailed,
            url: url.to_string(),
            hostname: hostname.clone(),
            resolved_ip: None,
        })?;
        let family = if address.is_ipv4() { 4 } else { 6 };
        vec![ResolvedRecord { address, family }]
    } else {
        let resolver: &dyn ResolveHost = opts.resolve_host.unwrap_or(&SystemResolver);
        resolver
            .resolve(&hostname)
            .map_err(|_| WebhookUrlUnsafeError {
                reason: WebhookUrlUnsafeReason::DnsResolutionFailed,
                url: url.to_string(),
                hostname: hostname.clone(),
                resolved_ip: None,
            })?
    };

    if records.is_empty() {
        return Err(WebhookUrlUnsafeError {
            reason: WebhookUrlUnsafeReason::NoDnsRecords,
            url: url.to_string(),
            hostname,
            resolved_ip: None,
        });
    }

    // ANY blocked IP fails the WHOLE check — a hostname resolving to both 8.8.8.8
    // and 127.0.0.1 must be rejected. An attacker who can add a private IP to a
    // multi-A record gets no wiggle room.
    for rec in &records {
        if !allow_private && is_blocked_ip(rec.address) {
            return Err(WebhookUrlUnsafeError {
                reason: WebhookUrlUnsafeReason::BlockedIpRange,
                url: url.to_string(),
                hostname,
                resolved_ip: Some(rec.address.to_string()),
            });
        }
    }

    let first = records[0];
    Ok(AssertWebhookUrlSafeResult {
        resolved_ip: first.address,
        family: first.family,
        hostname,
    })
}

// ---------------------------------------------------------------------------
// IP-range blocklist (pure logic)
// ---------------------------------------------------------------------------

/// A blocked IP range: a CIDR plus the reason it is blocked.
#[derive(Debug, Clone, Copy)]
pub struct BlockedRange {
    /// The CIDR in `addr/prefix` form.
    pub cidr: &'static str,
    /// Why the range is blocked.
    pub reason: &'static str,
}

/// Canonical blocked IPv4 ranges.
///
/// Covers RFC 1918 private space, RFC 5737 documentation (TEST-NET 1/2/3),
/// RFC 6598 CGNAT, loopback, link-local (including cloud metadata
/// `169.254.169.254`), IETF assignment, RFC 2544 benchmarking, multicast,
/// reserved/future-use, and the limited broadcast address.
pub const BLOCKED_IPV4_RANGES: [BlockedRange; 15] = [
    BlockedRange {
        cidr: "0.0.0.0/8",
        reason: "current network / \"this host\"",
    },
    BlockedRange {
        cidr: "10.0.0.0/8",
        reason: "RFC 1918 private",
    },
    BlockedRange {
        cidr: "100.64.0.0/10",
        reason: "CGNAT (RFC 6598)",
    },
    BlockedRange {
        cidr: "127.0.0.0/8",
        reason: "loopback",
    },
    BlockedRange {
        cidr: "169.254.0.0/16",
        reason: "link-local (covers AWS/GCE/Azure metadata 169.254.169.254)",
    },
    BlockedRange {
        cidr: "172.16.0.0/12",
        reason: "RFC 1918 private",
    },
    BlockedRange {
        cidr: "192.0.0.0/24",
        reason: "IETF assignment",
    },
    BlockedRange {
        cidr: "192.0.2.0/24",
        reason: "TEST-NET-1 (RFC 5737)",
    },
    BlockedRange {
        cidr: "192.168.0.0/16",
        reason: "RFC 1918 private",
    },
    BlockedRange {
        cidr: "198.18.0.0/15",
        reason: "benchmarking",
    },
    BlockedRange {
        cidr: "198.51.100.0/24",
        reason: "TEST-NET-2 (RFC 5737)",
    },
    BlockedRange {
        cidr: "203.0.113.0/24",
        reason: "TEST-NET-3 (RFC 5737)",
    },
    BlockedRange {
        cidr: "224.0.0.0/4",
        reason: "multicast",
    },
    BlockedRange {
        cidr: "240.0.0.0/4",
        reason: "reserved / future use",
    },
    BlockedRange {
        cidr: "255.255.255.255/32",
        reason: "broadcast",
    },
];

/// Canonical blocked IPv6 ranges.
///
/// Covers the unspecified and loopback addresses, the IPv4-mapped range
/// (`::ffff:0:0/96`, whose embedded IPv4 is peeled and re-checked), NAT64
/// translation, the discard prefix, RFC 3849 documentation, RFC 4193 ULA,
/// link-local, multicast, AWS IMDS-v6, Teredo, and 6to4.
pub const BLOCKED_IPV6_RANGES: [BlockedRange; 12] = [
    BlockedRange {
        cidr: "::/128",
        reason: "unspecified",
    },
    BlockedRange {
        cidr: "::1/128",
        reason: "loopback",
    },
    BlockedRange {
        cidr: "::ffff:0:0/96",
        reason: "IPv4-mapped IPv6",
    },
    BlockedRange {
        cidr: "64:ff9b::/96",
        reason: "IPv4/IPv6 translation",
    },
    BlockedRange {
        cidr: "100::/64",
        reason: "discard prefix",
    },
    BlockedRange {
        cidr: "2001:db8::/32",
        reason: "documentation",
    },
    BlockedRange {
        cidr: "fc00::/7",
        reason: "unique-local (ULA)",
    },
    BlockedRange {
        cidr: "fe80::/10",
        reason: "link-local",
    },
    BlockedRange {
        cidr: "ff00::/8",
        reason: "multicast",
    },
    BlockedRange {
        cidr: "fd00:ec2::/32",
        reason: "AWS IMDS v6",
    },
    BlockedRange {
        cidr: "2001:0:0:1::/64",
        reason: "Teredo",
    },
    BlockedRange {
        cidr: "2002::/16",
        reason: "6to4",
    },
];

/// Returns `true` if `ip` falls within ANY entry of the canonical blocklist.
///
/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) have their embedded IPv4 peeled
/// and re-checked against the IPv4 list; the mapped `/96` range is also rejected
/// outright (no legitimate webhook target lives there).
#[must_use]
pub fn is_blocked_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_blocked_ipv4(v4),
        std::net::IpAddr::V6(v6) => is_blocked_ipv6(v6),
    }
}

/// Parse an IP string and classify it. A malformed string is blocked
/// (fail-closed). Accepts IPv4-mapped notation such as `::ffff:127.0.0.1`.
#[must_use]
pub fn is_blocked_ip_str(ip: &str) -> bool {
    let normalised = canonicalise_host(ip);
    match normalised.parse::<std::net::IpAddr>() {
        Ok(addr) => is_blocked_ip(addr),
        Err(_) => true,
    }
}

fn is_blocked_ipv4(addr: Ipv4Addr) -> bool {
    let num = u32::from(addr);
    BLOCKED_IPV4_RANGES
        .iter()
        .any(|r| ipv4_in_cidr(num, r.cidr))
}

fn is_blocked_ipv6(addr: Ipv6Addr) -> bool {
    let octets = addr.octets();

    // Peel IPv4-mapped IPv6 (::ffff:a.b.c.d): first 10 bytes zero, bytes 10/11 =
    // 0xff, last 4 bytes the embedded IPv4. Re-check the embedded address, then
    // reject the mapped range outright regardless.
    if octets[..10].iter().all(|&b| b == 0) && octets[10] == 0xff && octets[11] == 0xff {
        let embedded = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
        if is_blocked_ipv4(embedded) {
            return true;
        }
        return true;
    }

    BLOCKED_IPV6_RANGES
        .iter()
        .any(|r| ipv6_in_cidr(&octets, r.cidr))
}

/// Test whether an IPv4 (as a `u32`) is inside `cidr`.
fn ipv4_in_cidr(ip_num: u32, cidr: &str) -> bool {
    let Some((base, bits_str)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(bits) = bits_str.parse::<u32>() else {
        return false;
    };
    let Ok(base_addr) = base.parse::<Ipv4Addr>() else {
        return false;
    };
    let base_num = u32::from(base_addr);
    if bits == 0 {
        return true;
    }
    if bits >= 32 {
        return ip_num == base_num;
    }
    let mask = u32::MAX << (32 - bits);
    (ip_num & mask) == (base_num & mask)
}

/// Test whether an IPv6 (as 16 octets) is inside `cidr`.
fn ipv6_in_cidr(ip_bytes: &[u8; 16], cidr: &str) -> bool {
    let Some((base, bits_str)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(bits) = bits_str.parse::<usize>() else {
        return false;
    };
    let Ok(base_addr) = base.parse::<Ipv6Addr>() else {
        return false;
    };
    let base_bytes = base_addr.octets();

    let full_bytes = bits / 8;
    let rem_bits = bits % 8;
    for i in 0..full_bytes {
        if ip_bytes[i] != base_bytes[i] {
            return false;
        }
    }
    if rem_bits == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem_bits);
    (ip_bytes[full_bytes] & mask) == (base_bytes[full_bytes] & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- a deterministic stub transport for the wrapper's control flow ----

    struct StubTransport {
        responses: std::sync::Mutex<Vec<Result<FetchOutboundResult, OutboundError>>>,
        calls: std::sync::Mutex<usize>,
    }

    impl StubTransport {
        fn ok_once(status: u16, body: Vec<u8>) -> Self {
            Self {
                responses: std::sync::Mutex::new(vec![Ok(FetchOutboundResult {
                    status,
                    bytes: body,
                    duration_ms: 1,
                })]),
                calls: std::sync::Mutex::new(0),
            }
        }
        fn from(responses: Vec<Result<FetchOutboundResult, OutboundError>>) -> Self {
            Self {
                responses: std::sync::Mutex::new(responses),
                calls: std::sync::Mutex::new(0),
            }
        }
        fn call_count(&self) -> usize {
            *self.calls.lock().unwrap()
        }
    }

    impl FetchTransport for StubTransport {
        fn fetch(
            &self,
            _url: &str,
            _opts: &FetchOutboundOptions,
        ) -> Result<FetchOutboundResult, OutboundError> {
            let mut calls = self.calls.lock().unwrap();
            let idx = *calls;
            *calls += 1;
            let responses = self.responses.lock().unwrap();
            let pick = if idx < responses.len() {
                idx
            } else {
                responses.len() - 1
            };
            match &responses[pick] {
                Ok(r) => Ok(r.clone()),
                Err(e) => Err(clone_err(e)),
            }
        }
    }

    fn clone_err(e: &OutboundError) -> OutboundError {
        // Test stubs only ever replay Transport/Exhausted-class errors.
        OutboundError::Transport {
            url: String::new(),
            message: e.to_string(),
        }
    }

    struct RecordingClock {
        slept: std::sync::Mutex<Vec<Duration>>,
    }
    impl RecordingClock {
        fn new() -> Self {
            Self {
                slept: std::sync::Mutex::new(Vec::new()),
            }
        }
        fn millis(&self) -> Vec<f64> {
            self.slept
                .lock()
                .unwrap()
                .iter()
                .map(|d| d.as_secs_f64() * 1000.0)
                .collect()
        }
    }
    impl Clock for RecordingClock {
        fn sleep(&self, duration: Duration) {
            self.slept.lock().unwrap().push(duration);
        }
    }

    /// A jitter source that returns a fixed multiplier — fully deterministic.
    struct FixedJitter(f64);
    impl Jitter for FixedJitter {
        fn multiplier(&self, _attempt_index: usize) -> f64 {
            self.0
        }
    }

    fn cfg(deny: &[&str], retries: u32) -> WrapFetchOutboundConfig {
        WrapFetchOutboundConfig {
            deny_hosts: deny.iter().map(|s| s.to_string()).collect(),
            retry: RetryConfig {
                retries,
                ..RetryConfig::default()
            },
        }
    }

    fn run(
        transport: &dyn FetchTransport,
        audit: &mut Vec<HttpCallRecord>,
        config: &WrapFetchOutboundConfig,
        url: &str,
        opts: &FetchOutboundOptions,
    ) -> Result<FetchOutboundResult, OutboundError> {
        wrap_fetch_outbound(
            transport,
            audit,
            config,
            &ThreadSleepClock,
            &FixedJitter(1.0),
            url,
            opts,
        )
    }

    // ---- deny-host matching ----

    #[test]
    fn deny_exact_and_negative() {
        assert!(matches_deny_list("operator.example", &["operator.example"]));
        assert!(!matches_deny_list("other.example", &["operator.example"]));
    }

    #[test]
    fn deny_wildcard_subdomain_but_not_bare() {
        assert!(matches_deny_list(
            "api.operator.example",
            &["*.operator.example"]
        ));
        assert!(matches_deny_list(
            "nested.api.operator.example",
            &["*.operator.example"]
        ));
        assert!(!matches_deny_list(
            "operator.example",
            &["*.operator.example"]
        ));
    }

    #[test]
    fn deny_case_and_trailing_dot() {
        assert!(matches_deny_list(
            "Operator.Example.",
            &["operator.example"]
        ));
        assert!(matches_deny_list(
            "OPERATOR.EXAMPLE.",
            &["operator.example"]
        ));
    }

    #[test]
    fn deny_localhost_aliases() {
        assert!(matches_deny_list("[::1]", &["localhost"]));
        assert!(matches_deny_list("::1", &["localhost"]));
        assert!(matches_deny_list("0.0.0.0", &["localhost"]));
        assert!(matches_deny_list("169.254.169.254", &["localhost"]));
    }

    #[test]
    fn deny_127_slash8() {
        assert!(matches_deny_list("127.1.2.3", &["127.0.0.1"]));
        assert!(matches_deny_list("127.0.0.99", &["127.0.0.1"]));
        assert!(matches_deny_list("127.99.0.5", &["127.0.0.1"]));
    }

    #[test]
    fn deny_public_control_and_empty_list() {
        assert!(!matches_deny_list("8.8.8.8", &["localhost", "127.0.0.1"]));
        assert!(!matches_deny_list("operator.example", &[] as &[&str]));
        assert!(!matches_deny_list("127.0.0.1", &[] as &[&str]));
    }

    #[test]
    fn deny_hosts_default_constant() {
        assert_eq!(DENY_HOSTS_DEFAULT, ["localhost", "127.0.0.1"]);
    }

    // ---- wrapper: deny short-circuit ----

    #[test]
    fn wrap_deny_records_row_and_does_not_call_inner() {
        let transport = StubTransport::ok_once(200, vec![]);
        let mut audit = Vec::new();
        let err = run(
            &transport,
            &mut audit,
            &cfg(&["operator.example"], 0),
            "https://operator.example/x",
            &FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Https),
        )
        .unwrap_err();
        assert_eq!(err.code(), "SERVICE_INDEPENDENCE_VIOLATION");
        match err {
            OutboundError::DenyHost { host, url } => {
                assert_eq!(host, "operator.example");
                assert_eq!(url, "https://operator.example/x");
            }
            other => panic!("expected DenyHost, got {other:?}"),
        }
        assert_eq!(transport.call_count(), 0);
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].status, None);
        assert_eq!(audit[0].duration_ms, 0);
        assert_eq!(audit[0].purpose, HttpPurpose::Https);
    }

    // ---- wrapper: protocol / method ----

    #[test]
    fn wrap_rejects_non_http_protocols() {
        for (url, proto) in [
            ("data:text/plain;base64,SGVsbG8=", "data:"),
            ("file:///etc/passwd", "file:"),
            ("ws://example.com/", "ws:"),
        ] {
            let transport = StubTransport::ok_once(200, vec![]);
            let mut audit = Vec::new();
            let err = run(
                &transport,
                &mut audit,
                &cfg(&[], 0),
                url,
                &FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Https),
            )
            .unwrap_err();
            assert_eq!(err.code(), "UNSUPPORTED_PROTOCOL");
            match err {
                OutboundError::UnsupportedProtocol { protocol, .. } => assert_eq!(protocol, proto),
                other => panic!("expected UnsupportedProtocol, got {other:?}"),
            }
            assert_eq!(transport.call_count(), 0);
            assert_eq!(audit.len(), 1);
            assert_eq!(audit[0].method, HttpMethod::Get);
            assert_eq!(audit[0].status, None);
        }
    }

    #[test]
    fn parse_method_rejects_methods_outside_the_allowlist() {
        for m in ["DELETE", "PATCH", "HEAD", "OPTIONS"] {
            let err = parse_http_method(m, "https://example.com/x").unwrap_err();
            assert_eq!(err.code(), "UNSUPPORTED_METHOD");
            match err {
                OutboundError::UnsupportedMethod { method, .. } => assert_eq!(method, m),
                other => panic!("expected UnsupportedMethod, got {other:?}"),
            }
        }
        assert_eq!(
            parse_http_method("GET", "https://x/").unwrap(),
            HttpMethod::Get
        );
        assert_eq!(
            parse_http_method("POST", "https://x/").unwrap(),
            HttpMethod::Post
        );
        // PUT is admitted for the resumable-upload chunk path; it rides the same
        // deny-host / SSRF pre-flight as GET and POST.
        assert_eq!(
            parse_http_method("PUT", "https://x/").unwrap(),
            HttpMethod::Put
        );
    }

    #[test]
    fn wrap_rejects_webhook_purpose() {
        let transport = StubTransport::ok_once(200, vec![]);
        let mut audit = Vec::new();
        let err = run(
            &transport,
            &mut audit,
            &cfg(&[], 0),
            "https://example.com/",
            &FetchOutboundOptions::new(HttpMethod::Post, HttpPurpose::Webhook),
        )
        .unwrap_err();
        assert!(matches!(err, OutboundError::WebhookPurposeRejected { .. }));
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].purpose, HttpPurpose::Webhook);
        assert_eq!(audit[0].status, None);
    }

    // ---- wrapper: audit shape + ordering ----

    #[test]
    fn wrap_success_records_one_row() {
        let transport = StubTransport::ok_once(200, vec![1, 2, 3, 4]);
        let mut audit = Vec::new();
        let r = run(
            &transport,
            &mut audit,
            &cfg(&[], 0),
            "https://example.com/x",
            &FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Arweave),
        )
        .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].bytes, 4);
        assert_eq!(audit[0].purpose, HttpPurpose::Arweave);
        assert_eq!(audit[0].method, HttpMethod::Get);
    }

    #[test]
    fn wrap_errored_fetch_records_null_status_then_rethrows() {
        let transport = StubTransport::from(vec![Err(OutboundError::Transport {
            url: "https://example.com/x".into(),
            message: "boom".into(),
        })]);
        let mut audit = Vec::new();
        let err = run(
            &transport,
            &mut audit,
            &cfg(&[], 0),
            "https://example.com/x",
            &FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Cardano),
        )
        .unwrap_err();
        assert!(matches!(err, OutboundError::Transport { .. }));
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].status, None);
        assert_eq!(audit[0].bytes, 0);
    }

    // ---- wrapper: retry / backoff with injected clock + jitter ----

    #[test]
    fn retries_zero_single_attempt_returns_503() {
        let transport = StubTransport::ok_once(503, vec![]);
        let mut audit = Vec::new();
        let r = run(
            &transport,
            &mut audit,
            &cfg(&[], 0),
            "https://example.com/",
            &FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Https),
        )
        .unwrap();
        assert_eq!(r.status, 503);
        assert_eq!(transport.call_count(), 1);
        assert_eq!(audit.len(), 1);
    }

    #[test]
    fn retry_503_then_200_records_two_rows() {
        let transport = StubTransport::from(vec![
            Ok(FetchOutboundResult {
                status: 503,
                bytes: vec![],
                duration_ms: 1,
            }),
            Ok(FetchOutboundResult {
                status: 200,
                bytes: vec![1],
                duration_ms: 1,
            }),
        ]);
        let mut audit = Vec::new();
        let clock = RecordingClock::new();
        let r = wrap_fetch_outbound(
            &transport,
            &mut audit,
            &cfg(&[], 3),
            &clock,
            &FixedJitter(1.0),
            "https://example.com/",
            &FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Https),
        )
        .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(
            audit.iter().map(|a| a.status).collect::<Vec<_>>(),
            vec![Some(503), Some(200)]
        );
        // One backoff before attempt 2, base 1000ms × jitter 1.0.
        assert_eq!(clock.millis(), vec![1000.0]);
    }

    #[test]
    fn retry_exhausted_wraps_in_exhausted_error() {
        let transport = StubTransport::from(vec![Ok(FetchOutboundResult {
            status: 503,
            bytes: vec![],
            duration_ms: 1,
        })]);
        let mut audit = Vec::new();
        let clock = RecordingClock::new();
        let err = wrap_fetch_outbound(
            &transport,
            &mut audit,
            &cfg(&[], 3),
            &clock,
            &FixedJitter(1.0),
            "https://example.com/",
            &FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Https),
        )
        .unwrap_err();
        match err {
            OutboundError::Exhausted {
                attempts,
                last_status,
                ..
            } => {
                assert_eq!(attempts, 4);
                assert_eq!(last_status, Some(503));
            }
            other => panic!("expected Exhausted, got {other:?}"),
        }
        assert_eq!(audit.len(), 4);
        // Backoff before attempts 2, 3, 4 → bases 1000, 2000, 4000 × jitter 1.0.
        assert_eq!(clock.millis(), vec![1000.0, 2000.0, 4000.0]);
    }

    #[test]
    fn backoff_jitter_band_is_bounded() {
        // The default RandomJitter must keep every sample within ±25% of base.
        let j = RandomJitter;
        for _ in 0..200 {
            let ms = backoff_jittered_ms(0, &j);
            assert!((750.0..=1250.0).contains(&ms), "out of band: {ms}");
        }
    }

    #[test]
    fn retryable_statuses_empty_disables_status_retry() {
        let transport = StubTransport::ok_once(503, vec![]);
        let mut audit = Vec::new();
        let config = WrapFetchOutboundConfig {
            deny_hosts: vec![],
            retry: RetryConfig {
                retries: 3,
                retryable_statuses: vec![],
            },
        };
        let r = run(
            &transport,
            &mut audit,
            &config,
            "https://example.com/",
            &FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Https),
        )
        .unwrap();
        assert_eq!(r.status, 503);
        assert_eq!(transport.call_count(), 1);
        assert_eq!(audit.len(), 1);
    }

    // ---- size-cap (pure read_body_capped is exercised through tests/) ----

    // ---- IP classification ----

    fn ip(s: &str) -> std::net::IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ipv4_ranges_all_blocked() {
        for s in [
            "0.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(is_blocked_ip(ip(s)), "expected {s} blocked");
        }
    }

    #[test]
    fn ipv4_public_not_blocked() {
        for s in ["8.8.8.8", "1.1.1.1", "9.9.9.9", "192.0.1.1"] {
            assert!(!is_blocked_ip(ip(s)), "expected {s} allowed");
        }
    }

    #[test]
    fn ipv6_ranges_all_blocked() {
        for s in [
            "::",
            "::1",
            "64:ff9b::1",
            "100::1",
            "2001:db8::1",
            "fd12:3456:789a:1::1",
            "fe80::1",
            "ff02::1",
            "fd00:ec2::1",
            "2001:0:0:1::1",
            "2002::1",
        ] {
            assert!(is_blocked_ip(ip(s)), "expected {s} blocked");
        }
    }

    #[test]
    fn ipv6_public_not_blocked() {
        for s in ["2606:4700:4700::1111", "2001:4860:4860::8888"] {
            assert!(!is_blocked_ip(ip(s)), "expected {s} allowed");
        }
    }

    #[test]
    fn ipv4_mapped_ipv6_peeled_and_blocked() {
        assert!(is_blocked_ip_str("::ffff:127.0.0.1"));
        assert!(is_blocked_ip_str("::ffff:10.0.0.1"));
        assert!(is_blocked_ip_str("::ffff:169.254.169.254"));
        // The mapped /96 itself is blocked even for a public embedded IPv4.
        assert!(is_blocked_ip_str("::ffff:8.8.8.8"));
        assert!(is_blocked_ip_str("::ffff:0a00:0001"));
    }

    #[test]
    fn malformed_ip_strings_fail_closed() {
        assert!(is_blocked_ip_str(""));
        assert!(is_blocked_ip_str("not-an-ip"));
        assert!(is_blocked_ip_str("999.0.0.1"));
    }

    #[test]
    fn range_constants_have_expected_counts() {
        assert_eq!(BLOCKED_IPV4_RANGES.len(), 15);
        assert_eq!(BLOCKED_IPV6_RANGES.len(), 12);
    }

    // ---- assert_webhook_url_safe with stub resolver ----

    struct StubResolver(Vec<ResolvedRecord>);
    impl ResolveHost for StubResolver {
        fn resolve(&self, _hostname: &str) -> Result<Vec<ResolvedRecord>, String> {
            Ok(self.0.clone())
        }
    }
    struct FailingResolver;
    impl ResolveHost for FailingResolver {
        fn resolve(&self, _hostname: &str) -> Result<Vec<ResolvedRecord>, String> {
            Err("ENOTFOUND".into())
        }
    }

    fn rec(s: &str) -> ResolvedRecord {
        let address = ip(s);
        ResolvedRecord {
            address,
            family: if address.is_ipv4() { 4 } else { 6 },
        }
    }

    fn with_resolver<'a>(r: &'a dyn ResolveHost) -> AssertWebhookUrlSafeOptions<'a> {
        AssertWebhookUrlSafeOptions {
            allow_private_for_tests: false,
            resolve_host: Some(r),
        }
    }

    #[test]
    fn webhook_https_public_ip_allowed() {
        let resolver = StubResolver(vec![rec("93.184.216.34")]);
        let r =
            assert_webhook_url_safe("https://example.com/hook", &with_resolver(&resolver)).unwrap();
        assert_eq!(r.resolved_ip, ip("93.184.216.34"));
        assert_eq!(r.family, 4);
        assert_eq!(r.hostname, "example.com");
    }

    #[test]
    fn webhook_http_rejected_by_default() {
        let resolver = StubResolver(vec![rec("93.184.216.34")]);
        let err = assert_webhook_url_safe("http://example.com/hook", &with_resolver(&resolver))
            .unwrap_err();
        assert_eq!(err.reason, WebhookUrlUnsafeReason::UnsupportedProtocol);
    }

    #[test]
    fn webhook_non_http_schemes_rejected() {
        for url in [
            "data:text/plain;base64,SGVsbG8=",
            "file:///etc/passwd",
            "ftp://x/y",
        ] {
            let err =
                assert_webhook_url_safe(url, &AssertWebhookUrlSafeOptions::default()).unwrap_err();
            assert_eq!(err.reason, WebhookUrlUnsafeReason::UnsupportedProtocol);
        }
    }

    #[test]
    fn webhook_mixed_records_any_blocked_rejects() {
        let resolver = StubResolver(vec![rec("8.8.8.8"), rec("127.0.0.1")]);
        let err = assert_webhook_url_safe("https://attacker.example/x", &with_resolver(&resolver))
            .unwrap_err();
        assert_eq!(err.reason, WebhookUrlUnsafeReason::BlockedIpRange);
        assert_eq!(err.resolved_ip.as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn webhook_ipv6_blocked() {
        let resolver = StubResolver(vec![rec("fe80::1")]);
        let err = assert_webhook_url_safe("https://attacker.example/x", &with_resolver(&resolver))
            .unwrap_err();
        assert_eq!(err.reason, WebhookUrlUnsafeReason::BlockedIpRange);
    }

    #[test]
    fn webhook_dns_failure_and_empty() {
        let err =
            assert_webhook_url_safe("https://nope.invalid/x", &with_resolver(&FailingResolver))
                .unwrap_err();
        assert_eq!(err.reason, WebhookUrlUnsafeReason::DnsResolutionFailed);

        let empty = StubResolver(vec![]);
        let err =
            assert_webhook_url_safe("https://void.example/x", &with_resolver(&empty)).unwrap_err();
        assert_eq!(err.reason, WebhookUrlUnsafeReason::NoDnsRecords);
    }

    #[test]
    fn webhook_invalid_urls_rejected() {
        for url in ["", "not a url"] {
            let err =
                assert_webhook_url_safe(url, &AssertWebhookUrlSafeOptions::default()).unwrap_err();
            assert_eq!(err.reason, WebhookUrlUnsafeReason::InvalidUrl);
        }
    }

    #[test]
    fn webhook_ip_literals() {
        // Public IPv4 literal: no DNS consulted.
        let r = assert_webhook_url_safe(
            "https://8.8.8.8/hook",
            &AssertWebhookUrlSafeOptions::default(),
        )
        .unwrap();
        assert_eq!(r.resolved_ip, ip("8.8.8.8"));
        assert_eq!(r.family, 4);

        // Private / loopback literals rejected.
        let err = assert_webhook_url_safe(
            "https://127.0.0.1/hook",
            &AssertWebhookUrlSafeOptions::default(),
        )
        .unwrap_err();
        assert_eq!(err.reason, WebhookUrlUnsafeReason::BlockedIpRange);

        let err = assert_webhook_url_safe(
            "https://[fe80::1]/hook",
            &AssertWebhookUrlSafeOptions::default(),
        )
        .unwrap_err();
        assert_eq!(err.reason, WebhookUrlUnsafeReason::BlockedIpRange);

        let err = assert_webhook_url_safe(
            "https://[::1]/hook",
            &AssertWebhookUrlSafeOptions::default(),
        )
        .unwrap_err();
        assert_eq!(err.reason, WebhookUrlUnsafeReason::BlockedIpRange);
    }

    #[test]
    fn webhook_ipv4_mapped_loopback_via_resolver() {
        let resolver = StubResolver(vec![rec("::ffff:127.0.0.1")]);
        let err = assert_webhook_url_safe("https://sneaky.example/x", &with_resolver(&resolver))
            .unwrap_err();
        assert_eq!(err.reason, WebhookUrlUnsafeReason::BlockedIpRange);
    }

    #[test]
    fn webhook_metadata_ip_via_resolver() {
        let resolver = StubResolver(vec![rec("169.254.169.254")]);
        let err = assert_webhook_url_safe("https://metadata.example/x", &with_resolver(&resolver))
            .unwrap_err();
        assert_eq!(err.reason, WebhookUrlUnsafeReason::BlockedIpRange);
    }

    #[test]
    fn webhook_allow_private_for_tests_permits_http_loopback() {
        let opts = AssertWebhookUrlSafeOptions {
            allow_private_for_tests: true,
            resolve_host: None,
        };
        let r = assert_webhook_url_safe("http://127.0.0.1:3000/hook", &opts).unwrap();
        assert_eq!(r.resolved_ip, ip("127.0.0.1"));
    }

    #[test]
    fn webhook_error_carries_fields() {
        let resolver = StubResolver(vec![rec("10.0.0.1")]);
        let err =
            assert_webhook_url_safe("https://x.example/y", &with_resolver(&resolver)).unwrap_err();
        assert_eq!(err.code(), "WEBHOOK_URL_UNSAFE");
        assert_eq!(err.reason, WebhookUrlUnsafeReason::BlockedIpRange);
        assert_eq!(err.url, "https://x.example/y");
        assert_eq!(err.hostname, "x.example");
        assert_eq!(err.resolved_ip.as_deref(), Some("10.0.0.1"));
    }
}
