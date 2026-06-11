//! The webhook delivery path must ignore proxy environment inheritance.
//!
//! `ReqwestTransport::pinned` is the user-supplied-URL (webhook) transport: it
//! resolves the connection to the IP the SSRF guard already range-checked. reqwest
//! honours `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` from the environment by default,
//! which would route the socket through a proxy and *around* the IP pin — the
//! proxy could then reach a private host the range-block thought it had excluded.
//! The pinned client clears proxy inheritance; this test proves a proxy env var
//! does not change the connection target.
//!
//! It lives in its own integration binary because it mutates process-global env
//! vars. Cargo runs each `tests/*.rs` file as a separate process, so this binary
//! contains the single env-mutating test and cannot disturb the system-resolver
//! cases in `verifier_fetch.rs`.

#![cfg(feature = "client")]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use cardanowall::verifier::fetch::{
    FetchOutboundOptions, FetchTransport, HttpMethod, HttpPurpose, ReqwestTransport,
};

/// A minimal HTTP/1.1 200 response with an honest Content-Length.
fn http_200(body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// Bind a loopback listener and serve one connection, flipping `reached` when hit
/// and answering with `body`. Returns the bound port.
fn spawn_once(reached: Arc<AtomicBool>, body: &'static [u8]) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            reached.store(true, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(&http_200(body));
            let _ = stream.flush();
        }
    });
    port
}

#[test]
fn pinned_transport_ignores_proxy_env() {
    // The validated target the pin points at: reaching it directly returns its
    // distinctive body.
    let target_reached = Arc::new(AtomicBool::new(false));
    let target_port = spawn_once(Arc::clone(&target_reached), b"direct-ok");

    // A sentinel proxy the request must NEVER reach. If proxy-env inheritance were
    // honoured the pinned client would connect here instead of the target.
    let proxy_reached = Arc::new(AtomicBool::new(false));
    let proxy_port = spawn_once(Arc::clone(&proxy_reached), b"VIA-PROXY");

    let host = "webhook-target.invalid";
    let url = format!("http://{host}:{target_port}/hook");
    let proxy_url = format!("http://127.0.0.1:{proxy_port}");

    // This is the only test in this binary, so the global env mutation cannot race
    // another test. Set every proxy variable reqwest consults, then clear them.
    for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
        std::env::set_var(var, &proxy_url);
    }

    let pinned = ReqwestTransport::pinned(host, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let mut opts = FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Webhook);
    opts.max_bytes = Some(1024);
    let result = pinned.fetch(&url, &opts).unwrap();

    for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
        std::env::remove_var(var);
    }

    assert_eq!(result.status, 200);
    assert_eq!(
        result.bytes, b"direct-ok",
        "the pinned client must return the target's body, not the proxy's"
    );
    assert!(
        target_reached.load(Ordering::SeqCst),
        "the validated target must be reached directly"
    );
    assert!(
        !proxy_reached.load(Ordering::SeqCst),
        "an HTTP_PROXY/HTTPS_PROXY env var must not route the pinned connection"
    );
}
