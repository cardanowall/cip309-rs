//! Integration tests for the verifier's outbound-fetch / SSRF layer.
//!
//! The pure, I/O-free logic (deny-host matching, IP-range classification,
//! URL/protocol/method validation, retry/backoff with injected clock + jitter)
//! is exercised by the in-module unit tests. This binary pins the parts that can
//! only be proven over a real socket:
//!
//! - the streaming body-size cap (over-cap rejected; lying Content-Length
//!   rejected; at-cap allowed), the actual OOM guard against a hostile gateway;
//! - the audit record shape produced by a real round-trip;
//! - the DNS-rebinding mitigation: a [`ReqwestTransport::pinned`] resolver makes
//!   the TCP connection target exactly the IP the SSRF guard validated, and
//!   refuses to resolve any other hostname.
//!
//! Plus the full deny-host allow/deny matrix and the SSRF IP classification
//! matrix (one representative IP per blocked range, plus public controls), so
//! the security-critical logic is pinned from the integration boundary too. A
//! std-only loopback HTTP server backs the network cases; no extra crate is
//! pulled in.

use std::net::IpAddr;

use cardanowall::verifier::fetch::{
    assert_webhook_url_safe, is_blocked_ip, matches_deny_list, AssertWebhookUrlSafeOptions,
    ResolveHost, ResolvedRecord, WebhookUrlUnsafeReason, BLOCKED_IPV4_RANGES, BLOCKED_IPV6_RANGES,
    DEFAULT_OUTBOUND_MAX_BYTES, DENY_HOSTS_DEFAULT,
};

// ===========================================================================
// Default constants — pinned so a regression that silently drops them is caught.
// ===========================================================================

#[test]
fn default_constants_are_pinned() {
    assert_eq!(DEFAULT_OUTBOUND_MAX_BYTES, 64 * 1024 * 1024, "64 MiB");
    assert_eq!(DENY_HOSTS_DEFAULT, ["localhost", "127.0.0.1"]);
}

// ===========================================================================
// Deny-host matching matrix (ports every deny-hosts.test.ts / fetch-outbound
// matchesDenyList case).
// ===========================================================================

#[test]
fn deny_host_full_matrix() {
    // exact
    assert!(matches_deny_list("operator.example", &["operator.example"]));
    assert!(!matches_deny_list("other.example", &["operator.example"]));

    // wildcard subdomain (single + multi label), not bare
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

    // case + trailing-dot
    assert!(matches_deny_list(
        "Operator.Example.",
        &["operator.example"]
    ));

    // localhost aliases
    assert!(matches_deny_list("[::1]", &["localhost"]));
    assert!(matches_deny_list("::1", &["localhost"]));
    assert!(matches_deny_list("0.0.0.0", &["localhost"]));
    assert!(matches_deny_list("169.254.169.254", &["localhost"]));

    // 127/8
    assert!(matches_deny_list("127.1.2.3", &["127.0.0.1"]));
    assert!(matches_deny_list("127.0.0.99", &["127.0.0.1"]));

    // public control + empty list
    assert!(!matches_deny_list("8.8.8.8", &["localhost", "127.0.0.1"]));
    assert!(!matches_deny_list("operator.example", &[] as &[&str]));
    assert!(!matches_deny_list("127.0.0.1", &[] as &[&str]));

    // the default deny list, applied: loopback closed, public hosts pass
    assert!(matches_deny_list("localhost", &DENY_HOSTS_DEFAULT));
    assert!(matches_deny_list("127.5.5.5", &DENY_HOSTS_DEFAULT));
    assert!(matches_deny_list("[::1]", &DENY_HOSTS_DEFAULT));
    assert!(!matches_deny_list("8.8.8.8", &DENY_HOSTS_DEFAULT));
    assert!(!matches_deny_list("operator.example", &DENY_HOSTS_DEFAULT));
}

// ===========================================================================
// SSRF IP classification matrix — one representative IP per blocked range,
// plus public controls (ports ssrf-guard.test.ts isBlockedIp cases).
// ===========================================================================

/// One sample IP per IPv4 range, kept aligned with `BLOCKED_IPV4_RANGES`.
const IPV4_SAMPLES: [(&str, &str); 15] = [
    ("0.0.0.0/8", "0.0.0.1"),
    ("10.0.0.0/8", "10.0.0.1"),
    ("100.64.0.0/10", "100.64.0.1"),
    ("127.0.0.0/8", "127.0.0.1"),
    ("169.254.0.0/16", "169.254.169.254"),
    ("172.16.0.0/12", "172.16.0.1"),
    ("192.0.0.0/24", "192.0.0.1"),
    ("192.0.2.0/24", "192.0.2.1"),
    ("192.168.0.0/16", "192.168.1.1"),
    ("198.18.0.0/15", "198.18.0.1"),
    ("198.51.100.0/24", "198.51.100.1"),
    ("203.0.113.0/24", "203.0.113.1"),
    ("224.0.0.0/4", "224.0.0.1"),
    ("240.0.0.0/4", "240.0.0.1"),
    ("255.255.255.255/32", "255.255.255.255"),
];

/// One sample IP per IPv6 range, kept aligned with `BLOCKED_IPV6_RANGES`.
const IPV6_SAMPLES: [(&str, &str); 12] = [
    ("::/128", "::"),
    ("::1/128", "::1"),
    ("::ffff:0:0/96", "::ffff:1.2.3.4"),
    ("64:ff9b::/96", "64:ff9b::1"),
    ("100::/64", "100::1"),
    ("2001:db8::/32", "2001:db8::1"),
    ("fc00::/7", "fd12:3456:789a:1::1"),
    ("fe80::/10", "fe80::1"),
    ("ff00::/8", "ff02::1"),
    ("fd00:ec2::/32", "fd00:ec2::1"),
    ("2001:0:0:1::/64", "2001:0:0:1::1"),
    ("2002::/16", "2002::1"),
];

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn ipv4_sample_parity_with_range_table() {
    let mut documented: Vec<&str> = BLOCKED_IPV4_RANGES.iter().map(|r| r.cidr).collect();
    let mut sampled: Vec<&str> = IPV4_SAMPLES.iter().map(|(c, _)| *c).collect();
    documented.sort_unstable();
    sampled.sort_unstable();
    assert_eq!(sampled, documented, "every IPv4 range needs a sample");
}

#[test]
fn ipv6_sample_parity_with_range_table() {
    let mut documented: Vec<&str> = BLOCKED_IPV6_RANGES.iter().map(|r| r.cidr).collect();
    let mut sampled: Vec<&str> = IPV6_SAMPLES.iter().map(|(c, _)| *c).collect();
    documented.sort_unstable();
    sampled.sort_unstable();
    assert_eq!(sampled, documented, "every IPv6 range needs a sample");
}

#[test]
fn every_blocked_range_sample_is_blocked() {
    for (cidr, sample) in IPV4_SAMPLES {
        assert!(
            is_blocked_ip(ip(sample)),
            "{sample} ({cidr}) must be blocked"
        );
    }
    // ::ffff:1.2.3.4 is parsed via the mapped path inside is_blocked_ip_str;
    // here we exercise the parsed-IpAddr path for every other v6 sample.
    for (cidr, sample) in IPV6_SAMPLES {
        if let Ok(addr) = sample.parse::<IpAddr>() {
            assert!(is_blocked_ip(addr), "{sample} ({cidr}) must be blocked");
        }
    }
}

#[test]
fn public_ips_are_not_blocked() {
    for s in ["8.8.8.8", "1.1.1.1", "9.9.9.9", "192.0.1.1"] {
        assert!(!is_blocked_ip(ip(s)), "{s} must be allowed");
    }
    for s in ["2606:4700:4700::1111", "2001:4860:4860::8888"] {
        assert!(!is_blocked_ip(ip(s)), "{s} must be allowed");
    }
}

// ===========================================================================
// SSRF end-to-end via stub resolver (ports the assertWebhookUrlSafe DNS cases).
// ===========================================================================

struct StubResolver(Vec<ResolvedRecord>);
impl ResolveHost for StubResolver {
    fn resolve(&self, _hostname: &str) -> Result<Vec<ResolvedRecord>, String> {
        Ok(self.0.clone())
    }
}

fn rec(s: &str) -> ResolvedRecord {
    let address = ip(s);
    ResolvedRecord {
        address,
        family: if address.is_ipv4() { 4 } else { 6 },
    }
}

fn with_resolver(r: &dyn ResolveHost) -> AssertWebhookUrlSafeOptions<'_> {
    AssertWebhookUrlSafeOptions {
        allow_private_for_tests: false,
        resolve_host: Some(r),
    }
}

#[test]
fn ssrf_resolver_public_allowed_loopback_blocked() {
    let public = StubResolver(vec![rec("93.184.216.34")]);
    let ok = assert_webhook_url_safe("https://example.com/hook", &with_resolver(&public)).unwrap();
    assert_eq!(ok.resolved_ip, ip("93.184.216.34"));
    assert_eq!(ok.hostname, "example.com");

    let loop_back = StubResolver(vec![rec("127.0.0.1")]);
    let err =
        assert_webhook_url_safe("https://x.example/y", &with_resolver(&loop_back)).unwrap_err();
    assert_eq!(err.reason, WebhookUrlUnsafeReason::BlockedIpRange);
}

#[test]
fn ssrf_rebind_style_mixed_records_rejected() {
    // One of several A records is private → the whole hop is rejected.
    let mixed = StubResolver(vec![rec("8.8.8.8"), rec("8.8.4.4"), rec("10.0.0.1")]);
    let err =
        assert_webhook_url_safe("https://rebind.example/x", &with_resolver(&mixed)).unwrap_err();
    assert_eq!(err.reason, WebhookUrlUnsafeReason::BlockedIpRange);
    assert_eq!(err.resolved_ip.as_deref(), Some("10.0.0.1"));
}

// ===========================================================================
// Real-socket cases: a std-only loopback HTTP server.
//
// These cases drive bytes over a real socket through the production reqwest
// transport, so they compile only with the `client` feature. The deny-host and
// SSRF logic above is pure and runs in every build.
// ===========================================================================

#[cfg(feature = "client")]
mod real_socket {
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;

    use cardanowall::verifier::fetch::{
        fetch_outbound, FetchOutboundOptions, HttpMethod, HttpPurpose, OutboundError,
        ReqwestTransport, WrapFetchOutboundConfig, DENY_HOSTS_DEFAULT,
    };

    /// Spawn a one-shot loopback HTTP server. The handler is given the raw request
    /// bytes and returns the full raw response bytes to write back. Returns the bound
    /// `SocketAddr`. The server serves a single connection then exits.
    fn spawn_once<F>(handler: F) -> SocketAddr
    where
        F: FnOnce(&[u8]) -> Vec<u8> + Send + 'static,
    {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let resp = handler(&buf);
                let _ = stream.write_all(&resp);
                let _ = stream.flush();
            }
        });
        addr
    }

    /// Build a minimal HTTP/1.1 200 response with the given body and an honest
    /// Content-Length (unless `lie_length` overrides it).
    fn http_200(body: &[u8], lie_length: Option<usize>) -> Vec<u8> {
        let len = lie_length.unwrap_or(body.len());
        let mut out =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n")
                .into_bytes();
        out.extend_from_slice(body);
        out
    }

    fn http_url(addr: SocketAddr, path: &str) -> String {
        format!("http://{addr}{path}")
    }

    #[test]
    fn real_fetch_under_cap_returns_body_and_audit_row() {
        let addr = spawn_once(|_req| http_200(b"hello-world", None));
        let mut audit = Vec::new();
        let mut opts = FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Arweave);
        opts.max_bytes = Some(1024);
        let r = fetch_outbound(
            &http_url(addr, "/blob"),
            &opts,
            &mut audit,
            &WrapFetchOutboundConfig::default(),
        )
        .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.bytes, b"hello-world");

        // Audit row shape: one row, all six fields, snake-case purpose token.
        assert_eq!(audit.len(), 1);
        let row = &audit[0];
        assert_eq!(row.status, Some(200));
        assert_eq!(row.bytes, "hello-world".len() as u64);
        assert_eq!(row.method, HttpMethod::Get);
        assert_eq!(row.purpose.as_str(), "arweave");
        assert_eq!(row.url, http_url(addr, "/blob"));
    }

    #[test]
    fn real_fetch_body_over_cap_is_rejected() {
        let addr = spawn_once(|_req| http_200(&vec![b'x'; 4096], None));
        let mut audit = Vec::new();
        let mut opts = FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Arweave);
        opts.max_bytes = Some(1024);
        let err = fetch_outbound(
            &http_url(addr, "/big"),
            &opts,
            &mut audit,
            &WrapFetchOutboundConfig::default(),
        )
        .unwrap_err();
        assert_eq!(err.code(), "OUTBOUND_BODY_TOO_LARGE");
        match err {
            OutboundError::BodyTooLarge { limit_bytes, .. } => assert_eq!(limit_bytes, 1024),
            other => panic!("expected BodyTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn real_fetch_lying_content_length_over_cap_is_rejected() {
        // Declares a huge Content-Length but serves a tiny body. The fast-path
        // header check must bail before reading the body.
        let addr = spawn_once(|_req| http_200(b"xx", Some(999_999)));
        let mut audit = Vec::new();
        let mut opts = FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Arweave);
        opts.max_bytes = Some(1024);
        let err = fetch_outbound(
            &http_url(addr, "/liar"),
            &opts,
            &mut audit,
            &WrapFetchOutboundConfig::default(),
        )
        .unwrap_err();
        assert_eq!(err.code(), "OUTBOUND_BODY_TOO_LARGE");
    }

    #[test]
    fn real_fetch_exactly_at_cap_is_allowed() {
        let addr = spawn_once(|_req| http_200(&vec![7u8; 1024], None));
        let mut audit = Vec::new();
        let mut opts = FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Arweave);
        opts.max_bytes = Some(1024);
        let r = fetch_outbound(
            &http_url(addr, "/exact"),
            &opts,
            &mut audit,
            &WrapFetchOutboundConfig::default(),
        )
        .unwrap();
        assert_eq!(r.bytes.len(), 1024);
    }

    #[test]
    fn real_fetch_deny_host_short_circuits_before_socket() {
        // 127.0.0.1 is in the default deny list; the wrapper must reject before any
        // connection, so the server (which we never spawn) is irrelevant.
        let config = WrapFetchOutboundConfig {
            deny_hosts: DENY_HOSTS_DEFAULT.iter().map(|s| s.to_string()).collect(),
            ..WrapFetchOutboundConfig::default()
        };
        let mut audit = Vec::new();
        let err = fetch_outbound(
            "http://127.0.0.1:9/never",
            &FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Https),
            &mut audit,
            &config,
        )
        .unwrap_err();
        assert_eq!(err.code(), "SERVICE_INDEPENDENCE_VIOLATION");
        assert_eq!(audit.len(), 1);
        // No response was received: the schema-required status is null.
        assert_eq!(audit[0].status, None);
    }

    // ===========================================================================
    // DNS-rebind connection pinning: the pinned transport must connect to the IP
    // the SSRF guard validated, and must refuse to resolve any other host.
    // ===========================================================================

    #[test]
    fn pinned_transport_connects_to_validated_ip() {
        use cardanowall::verifier::fetch::FetchTransport;

        let served = Arc::new(AtomicBool::new(false));
        let served_clone = Arc::clone(&served);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                served_clone.store(true, Ordering::SeqCst);
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(&http_200(b"pinned-ok", None));
                let _ = stream.flush();
            }
        });

        // Use a hostname that does NOT resolve in DNS, but pin it to the loopback IP
        // the server is on. If pinning works the request still lands on our socket;
        // without pinning the name resolution would fail.
        let host = "webhook-target.invalid";
        let pinned = ReqwestTransport::pinned(host, IpAddr::V4(Ipv4Addr::LOCALHOST));
        let url = format!("http://{host}:{}/hook", addr.port());
        let mut opts = FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Webhook);
        opts.max_bytes = Some(1024);
        let result = pinned.fetch(&url, &opts).unwrap();
        assert_eq!(result.status, 200);
        assert_eq!(result.bytes, b"pinned-ok");
        assert!(
            served.load(Ordering::SeqCst),
            "the pinned IP's server must have been reached"
        );
    }

    #[test]
    fn pinned_transport_refuses_unexpected_host() {
        use cardanowall::verifier::fetch::FetchTransport;

        // Pin host A, then request host B. The custom resolver refuses B, so the
        // request fails as a transport error rather than silently re-resolving.
        let pinned =
            ReqwestTransport::pinned("pinned-host.invalid", IpAddr::V4(Ipv4Addr::LOCALHOST));
        let opts = FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Webhook);
        let err = pinned
            .fetch("http://other-host.invalid/hook", &opts)
            .unwrap_err();
        assert_eq!(err.code(), "OUTBOUND_TRANSPORT");
    }

    // ===========================================================================
    // SSRF: redirects must NOT be followed. The deny-host / SSRF guard validates
    // only the original URL, so an un-rechecked `Location` hop could pivot the
    // fetch into the internal network. A 3xx must surface as a non-200 status.
    // ===========================================================================

    /// Build a minimal HTTP/1.1 3xx redirect response pointing at `location`.
    fn http_redirect(status_line: &str, location: &str) -> Vec<u8> {
        format!(
        "HTTP/1.1 {status_line}\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
    }

    #[test]
    fn redirect_is_not_followed_to_internal_host() {
        use cardanowall::verifier::fetch::FetchTransport;

        // The "internal" target: a loopback server that, if ever reached, returns a
        // body that would prove the redirect was followed. We assert it is NEVER hit.
        let internal_reached = Arc::new(AtomicBool::new(false));
        let internal_reached_clone = Arc::clone(&internal_reached);
        let internal = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let internal_addr = internal.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = internal.accept() {
                internal_reached_clone.store(true, Ordering::SeqCst);
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(&http_200(b"INTERNAL-SECRET", None));
                let _ = stream.flush();
            }
        });

        // The hostile gateway redirects to the internal server.
        let location = format!("http://127.0.0.1:{}/metadata", internal_addr.port());
        let gateway_addr = spawn_once(move |_req| http_redirect("302 Found", &location));

        // ReqwestTransport (the production verifier transport) must surface the 302,
        // not the internal body.
        let transport = ReqwestTransport::new();
        let mut opts = FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Arweave);
        opts.max_bytes = Some(1024);
        let result = transport
            .fetch(&http_url(gateway_addr, "/redirect"), &opts)
            .unwrap();

        assert_eq!(result.status, 302, "the 3xx must surface as the status");
        assert_ne!(
            result.bytes, b"INTERNAL-SECRET",
            "the internal body must never be returned"
        );
        assert!(
            !internal_reached.load(Ordering::SeqCst),
            "the redirect target must never be contacted"
        );
    }
}
