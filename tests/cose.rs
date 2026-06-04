//! COSE_Sign1 + Ed25519 byte-parity tests against the shared fixtures.
//!
//! These tests pin the Rust COSE layer against the exact same cross-implementation
//! vectors the TypeScript (`@cardanowall/sdk-ts`) and Python (`cardanowall-sdk`)
//! SDKs assert on:
//!
//! - `sig/ed25519-kat.json`, `sig/ed25519-roundtrip.json` — Ed25519 sign/derive
//!   KATs (RFC 8032 §7.1 + project roundtrip vectors).
//! - `sig/ed25519-zip215.json` — strict-verify (`zip215: false`) accept/reject.
//! - `cose/sig-structure.json` — RFC 9052 §4.4 Sig_structure byte layout.
//! - `cose/sign1-build.json` — full COSE_Sign1 build (RFC general form +
//!   Label 309 record signatures) → exact bytes.
//! - `cose/sign1-verify.json` — COSE_Sign1 verify accept/reject by error code.
//! - `cose/sign1-strict-ed25519.json` — strict-Ed25519 rejection within COSE.
//!
//! Fixtures are path-referenced from the `crypto-core` tree (the source of
//! truth), never copied. Where a behaviour is exercised only by an inline test in
//! the reference (hashed mode, cose-key, empty-protected / detached forms), the
//! case is reproduced here directly.

mod common;

use cardanowall::cbor::{encode_canonical_cbor, CborValue};
use cardanowall::cose::{
    build_label309_sig_structure, build_sig_structure, cose_sign1_label309_assemble,
    cose_sign1_label309_build, cose_sign1_label309_prepare, cose_sign1_label309_verify,
    decode_cose_sign1, ed25519_public_key_from_seed, ed25519_sign, ed25519_verify,
    encode_cose_sign1, parse_cose_key_ed25519, CoseHeader, CoseVerifyErrorCode, CoseVerifyResult,
    Label309Signer, CARDANO_POE_SIG_DOMAIN_PREFIX,
};
use cardanowall::hex;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn h(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("valid hex in fixture")
}

fn seed32(hex_str: &str) -> [u8; 32] {
    h(hex_str).as_slice().try_into().expect("32-byte seed")
}

fn s(value: &Value) -> &str {
    value.as_str().expect("fixture field is a string")
}

fn vectors<'a>(corpus: &'a Value, key: &str) -> &'a Vec<Value> {
    corpus[key].as_array().expect("fixture array")
}

/// Build a Label 309 path-1 protected header `{1: -8, 4: <32B pubkey>}`.
fn protected_header_with_kid(pubkey: &[u8]) -> CoseHeader {
    CoseHeader::new()
        .with_int(1, CborValue::int(-8))
        .with_int(4, CborValue::bytes(pubkey.to_vec()))
}

fn load(rel: &str) -> Value {
    common::read_fixture_json(&common::crypto_core_fixtures().join(rel))
}

// ---------------------------------------------------------------------------
// Domain prefix
// ---------------------------------------------------------------------------

#[test]
fn domain_prefix_is_the_spec_pinned_25_byte_string() {
    assert_eq!(CARDANO_POE_SIG_DOMAIN_PREFIX, "cardano-poe-record-sig-v1");
    assert_eq!(CARDANO_POE_SIG_DOMAIN_PREFIX.len(), 25);
    assert_eq!(
        hex::encode(CARDANO_POE_SIG_DOMAIN_PREFIX.as_bytes()),
        "63617264616e6f2d706f652d7265636f72642d7369672d7631"
    );
}

// ---------------------------------------------------------------------------
// Ed25519 KAT + roundtrip
// ---------------------------------------------------------------------------

fn assert_ed25519_kat_corpus(rel: &str, min_count: usize) {
    let corpus = load(rel);
    let vs = vectors(&corpus, "vectors");
    assert!(
        vs.len() >= min_count,
        "{rel}: expected >= {min_count} vectors, got {}",
        vs.len()
    );
    for v in vs {
        let name = s(&v["name"]);
        let seed = seed32(s(&v["seed_hex"]));
        let message = h(s(&v["message_hex"]));

        let pubkey = ed25519_public_key_from_seed(&seed);
        assert_eq!(
            hex::encode(&pubkey),
            s(&v["expected_public_key_hex"]),
            "{name}: public key"
        );

        let signature = ed25519_sign(&seed, &message);
        assert_eq!(
            hex::encode(&signature),
            s(&v["expected_signature_hex"]),
            "{name}: signature"
        );

        assert!(
            ed25519_verify(&pubkey, &message, &signature),
            "{name}: self-verify"
        );
    }
}

#[test]
fn ed25519_kat_vectors() {
    // RFC 8032 §7.1 Test 1/2/3.
    assert_ed25519_kat_corpus("sig/ed25519-kat.json", 3);
}

#[test]
fn ed25519_roundtrip_vectors() {
    assert_ed25519_kat_corpus("sig/ed25519-roundtrip.json", 4);
}

/// Assert that `ed25519_verify` reproduces the fixture's accept/reject verdict
/// for every vector of a `{public_key_hex, message_hex, signature_hex,
/// expected_valid}` corpus. Returns `(total, accepts)` for the caller to pin.
fn assert_ed25519_strict_corpus(rel: &str) -> (usize, usize) {
    let corpus = load(rel);
    let vs = vectors(&corpus, "vectors");
    let mut accepts = 0usize;
    for v in vs {
        let name = s(&v["name"]);
        let pubkey = h(s(&v["public_key_hex"]));
        let message = h(s(&v["message_hex"]));
        let signature = h(s(&v["signature_hex"]));
        let expected = v["expected_valid"].as_bool().expect("expected_valid bool");
        if expected {
            accepts += 1;
        }
        assert_eq!(
            ed25519_verify(&pubkey, &message, &signature),
            expected,
            "{name}: strict (non-cofactored) verdict must match fixture"
        );
    }
    (vs.len(), accepts)
}

#[test]
fn ed25519_zip215_strict_verdicts() {
    let (total, _accepts) = assert_ed25519_strict_corpus("sig/ed25519-zip215.json");
    assert_eq!(total, 1, "zip215 corpus size");
}

#[test]
fn ed25519_torsion_cctv_strict_verdicts() {
    // The C2SP/CCTV ed25519 torsion corpus: every vector's strict
    // (non-cofactored, RFC 8032 §5.1.7) verdict must match the PyNaCl/libsodium
    // consensus, which equals ed25519-dalek `verify_strict`. 914 vectors, 43 of
    // which the strict rule accepts.
    let (total, accepts) = assert_ed25519_strict_corpus("sig/ed25519-torsion-cctv.json");
    assert_eq!(total, 914, "torsion-cctv corpus size");
    assert_eq!(accepts, 43, "strict-accept count");
}

// ---------------------------------------------------------------------------
// Sig_structure
// ---------------------------------------------------------------------------

#[test]
fn sig_structure_build_vectors() {
    let corpus = load("cose/sig-structure.json");
    let vs = vectors(&corpus, "vectors");
    assert_eq!(vs.len(), 3, "sig-structure corpus size");
    for v in vs {
        let name = s(&v["name"]);
        assert_eq!(s(&v["context"]), "Signature1", "{name}: context");
        let result = build_sig_structure(
            &h(s(&v["body_protected_bytes_hex"])),
            &h(s(&v["external_aad_hex"])),
            &h(s(&v["payload_hex"])),
        );
        assert_eq!(
            hex::encode(&result),
            s(&v["expected_sig_structure_hex"]),
            "{name}: Sig_structure bytes"
        );
    }
}

// ---------------------------------------------------------------------------
// COSE_Sign1 build
// ---------------------------------------------------------------------------

/// Build the general RFC 9052 COSE_Sign1 the way the reference `cose_sign1_build`
/// helper does: Sig_structure over the given payload + external_aad, Ed25519-sign
/// it, then emit the array with the payload attached or detached per the vector.
fn build_general_cose_sign1(v: &Value) -> Vec<u8> {
    let protected = {
        let mut header = CoseHeader::new();
        for pair in v["protected_header_int_pairs"].as_array().unwrap() {
            let p = pair.as_array().unwrap();
            header = header.with_int(
                p[0].as_i64().unwrap(),
                CborValue::int(p[1].as_i64().unwrap()),
            );
        }
        header
    };
    let unprotected = {
        let mut header = CoseHeader::new();
        for pair in v["unprotected_header_int_bytes_pairs"].as_array().unwrap() {
            let p = pair.as_array().unwrap();
            header = header.with_int(p[0].as_i64().unwrap(), CborValue::bytes(h(s(&p[1]))));
        }
        header
    };
    let protected_bytes = if protected.is_empty() {
        Vec::new()
    } else {
        encode_canonical_cbor(&protected.to_cbor()).unwrap()
    };
    let payload = h(s(&v["payload_hex"]));
    let external_aad = h(s(&v["external_aad_hex"]));
    let sig_structure = build_sig_structure(&protected_bytes, &external_aad, &payload);
    let seed = seed32(s(&v["signer_secret_key_hex"]));
    let signature = ed25519_sign(&seed, &sig_structure);
    let detached = v["detached"].as_bool().unwrap();
    encode_cose_sign1(
        &protected,
        &unprotected,
        if detached { None } else { Some(&payload) },
        &signature,
    )
    .unwrap()
}

#[test]
fn cose_sign1_build_general_rfc_vectors() {
    let corpus = load("cose/sign1-build.json");
    let vs = vectors(&corpus, "vectors");
    assert_eq!(vs.len(), 2, "general build corpus size");
    for v in vs {
        let name = s(&v["name"]);
        let cose = build_general_cose_sign1(v);
        assert_eq!(
            hex::encode(&cose),
            s(&v["expected_cose_sign1_hex"]),
            "{name}: COSE_Sign1 bytes"
        );
    }
}

#[test]
fn cose_sign1_label309_build_and_sig_structure_vectors() {
    let corpus = load("cose/sign1-build.json");
    let vs = vectors(&corpus, "cardano_poe_vectors");
    assert_eq!(vs.len(), 4, "cardano_poe build corpus size");
    let mut label309_count = 0usize;
    for v in vs {
        let name = s(&v["name"]);
        let pubkey = h(s(&v["signer_public_key_hex"]));
        let body = h(s(&v["record_body_cbor_hex"]));
        let seed = seed32(s(&v["signer_secret_key_hex"]));
        let protected = protected_header_with_kid(&pubkey);

        // Sig_structure byte-pin.
        let protected_bytes = encode_canonical_cbor(&protected.to_cbor()).unwrap();
        let sig_structure = build_label309_sig_structure(&protected_bytes, &body);
        assert_eq!(
            hex::encode(&sig_structure),
            s(&v["expected_sig_structure_hex"]),
            "{name}: Sig_structure"
        );
        // external_aad forced to h'' lands at byte index 52 (84 | "Signature1"(11)
        // | 58 26 | protected(38) | 0x40).
        assert_eq!(sig_structure[52], 0x40, "{name}: external_aad is h''");

        // Seed path → full COSE_Sign1 byte-pin.
        let cose = cose_sign1_label309_build(
            &protected,
            &CoseHeader::new(),
            &body,
            Label309Signer::Seed(&seed),
        )
        .unwrap();
        assert_eq!(
            hex::encode(&cose),
            s(&v["expected_cose_sign1_hex"]),
            "{name}: COSE_Sign1 (seed path)"
        );

        // Signature byte-pin (when present).
        if let Some(expected_sig) = v.get("expected_signature_hex").and_then(Value::as_str) {
            let signature = ed25519_sign(&seed, &sig_structure);
            assert_eq!(hex::encode(&signature), expected_sig, "{name}: signature");
        }

        if name.starts_with("label309-") {
            label309_count += 1;
        }
    }
    assert!(
        label309_count >= 3,
        "cross-SDK parity gate: at least 3 label309-* vectors, got {label309_count}"
    );
}

#[test]
fn cose_sign1_label309_build_signer_closure_path_is_byte_identical() {
    let corpus = load("cose/sign1-build.json");
    for v in vectors(&corpus, "cardano_poe_vectors") {
        let name = s(&v["name"]);
        let pubkey = h(s(&v["signer_public_key_hex"]));
        let body = h(s(&v["record_body_cbor_hex"]));
        let seed = seed32(s(&v["signer_secret_key_hex"]));
        let protected = protected_header_with_kid(&pubkey);

        // The closure receives the assembled Sig_structure bytes and returns the
        // 64-byte signature — composer-side path where the seed never escapes.
        let captured = std::cell::RefCell::new(Vec::<Vec<u8>>::new());
        let closure = |sig_structure: &[u8]| -> Vec<u8> {
            captured.borrow_mut().push(sig_structure.to_vec());
            ed25519_sign(&seed, sig_structure).to_vec()
        };
        let cose = cose_sign1_label309_build(
            &protected,
            &CoseHeader::new(),
            &body,
            Label309Signer::Closure(&closure),
        )
        .unwrap();
        assert_eq!(
            hex::encode(&cose),
            s(&v["expected_cose_sign1_hex"]),
            "{name}: closure path COSE_Sign1"
        );
        let captured = captured.into_inner();
        assert_eq!(captured.len(), 1, "{name}: closure invoked exactly once");
        assert_eq!(
            hex::encode(&captured[0]),
            s(&v["expected_sig_structure_hex"]),
            "{name}: closure saw the spec Sig_structure"
        );
    }
}

#[test]
fn cose_sign1_label309_build_rejects_bad_signer() {
    let corpus = load("cose/sign1-build.json");
    let v = &vectors(&corpus, "cardano_poe_vectors")[0];
    let pubkey = h(s(&v["signer_public_key_hex"]));
    let body = h(s(&v["record_body_cbor_hex"]));
    let protected = protected_header_with_kid(&pubkey);

    // A closure that returns a 63-byte value is rejected as SIGNER_NOT_PROVIDED
    // (the twins reuse that code for the bad-length case).
    let short = |_: &[u8]| -> Vec<u8> { vec![0u8; 63] };
    let err = cose_sign1_label309_build(
        &protected,
        &CoseHeader::new(),
        &body,
        Label309Signer::Closure(&short),
    )
    .unwrap_err();
    assert_eq!(err.code(), "SIGNER_NOT_PROVIDED");
}

// ---------------------------------------------------------------------------
// Off-host prepare / assemble
// ---------------------------------------------------------------------------

#[test]
fn label309_prepare_assemble_reproduces_build_bytes() {
    let corpus = load("cose/sign1-build.json");
    for v in vectors(&corpus, "cardano_poe_vectors") {
        let name = s(&v["name"]);
        let pubkey = h(s(&v["signer_public_key_hex"]));
        let body = h(s(&v["record_body_cbor_hex"]));
        let seed = seed32(s(&v["signer_secret_key_hex"]));
        let protected = protected_header_with_kid(&pubkey);

        // prepare → exact bytes the external signer signs (== the build Sig_structure).
        let prepared = cose_sign1_label309_prepare(&protected, &CoseHeader::new(), &body).unwrap();
        assert_eq!(
            hex::encode(&prepared.sig_structure),
            s(&v["expected_sig_structure_hex"]),
            "{name}: prepared Sig_structure"
        );

        // External signer signs those bytes; assemble folds in the signature.
        let signature = ed25519_sign(&seed, &prepared.sig_structure);
        let cose = cose_sign1_label309_assemble(&prepared, &signature).unwrap();
        assert_eq!(
            hex::encode(&cose),
            s(&v["expected_cose_sign1_hex"]),
            "{name}: assembled COSE_Sign1 matches build output"
        );
    }
}

#[test]
fn label309_assemble_rejects_non_64_byte_signature() {
    let protected = protected_header_with_kid(&[0xab; 32]);
    let prepared =
        cose_sign1_label309_prepare(&protected, &CoseHeader::new(), &h("a16161182a")).unwrap();
    let err = cose_sign1_label309_assemble(&prepared, &[0u8; 63]).unwrap_err();
    assert_eq!(err.code(), "SIGNER_NOT_PROVIDED");
}

// ---------------------------------------------------------------------------
// COSE_Sign1 verify
// ---------------------------------------------------------------------------

fn assert_verify_result(result: &CoseVerifyResult, expected: &Value, name: &str) {
    if expected["ok"].as_bool().unwrap() {
        match result {
            CoseVerifyResult::Ok { signer_key, alg } => {
                if let Some(k) = expected.get("signer_key_hex").and_then(Value::as_str) {
                    assert_eq!(hex::encode(signer_key), k, "{name}: signer key");
                }
                if let Some(a) = expected.get("alg").and_then(Value::as_i64) {
                    assert_eq!(*alg, a, "{name}: alg");
                }
            }
            CoseVerifyResult::Err(code) => {
                panic!("{name}: expected ok, got {}", code.code());
            }
        }
    } else {
        match result {
            CoseVerifyResult::Err(code) => {
                assert_eq!(
                    code.code(),
                    s(&expected["error_code"]),
                    "{name}: error code"
                );
            }
            CoseVerifyResult::Ok { .. } => panic!("{name}: expected error, got ok"),
        }
    }
}

/// The `sign1-verify.json` general vectors carry an attached payload, so the
/// reference verifies them via `cose_sign1_verify` (external_aad arg, attached
/// or detached payload). The Rust Label 309 verifier mandates a detached payload,
/// so reproduce the general RFC 9052 verify here over the same primitives.
fn verify_general(v: &Value) -> CoseVerifyResult {
    let message = h(s(&v["message_hex"]));
    let external_aad = h(s(&v["external_aad_hex"]));
    let expected_signer_key = v
        .get("expected_signer_key_hex")
        .and_then(Value::as_str)
        .map(h);
    let detached_payload = v.get("detached_payload_hex").and_then(Value::as_str).map(h);

    let decoded = match decode_cose_sign1(&message) {
        Ok(d) => d,
        Err(_) => return CoseVerifyResult::Err(CoseVerifyErrorCode::MalformedSigCose),
    };
    // Resolve alg = -8 (UNSUPPORTED_SIG_ALG otherwise).
    if decoded.protected_header.alg() != Some(-8) {
        return CoseVerifyResult::Err(CoseVerifyErrorCode::UnsupportedSigAlg);
    }
    // Resolve signer key: 32-byte kid (protected) else expected_signer_key.
    let signer_key = match decoded.protected_header.kid() {
        Some(k) => k,
        None => match &expected_signer_key {
            Some(k) if k.len() == 32 => k.as_slice().try_into().unwrap(),
            _ => return CoseVerifyResult::Err(CoseVerifyErrorCode::KidUnresolved),
        },
    };
    // Payload: attached on the wire else the detached argument.
    let payload = match (&decoded.payload, &detached_payload) {
        (Some(p), _) => p.clone(),
        (None, Some(p)) => p.clone(),
        (None, None) => return CoseVerifyResult::Err(CoseVerifyErrorCode::MalformedSigCose),
    };
    let sig_structure = build_sig_structure(&decoded.protected_bytes, &external_aad, &payload);
    if ed25519_verify(&signer_key, &sig_structure, &decoded.signature) {
        CoseVerifyResult::Ok {
            signer_key,
            alg: -8,
        }
    } else {
        CoseVerifyResult::Err(CoseVerifyErrorCode::SignatureInvalid)
    }
}

#[test]
fn cose_sign1_verify_general_rfc_corpus() {
    let corpus = load("cose/sign1-verify.json");
    let vs = vectors(&corpus, "vectors");
    assert_eq!(vs.len(), 6, "general verify corpus size");
    for v in vs {
        let name = s(&v["name"]);
        let result = verify_general(v);
        assert_verify_result(&result, &v["expected_result"], name);
    }
}

#[test]
fn cose_sign1_label309_verify_corpus() {
    let corpus = load("cose/sign1-verify.json");
    let vs = vectors(&corpus, "cardano_poe_vectors");
    assert_eq!(vs.len(), 4, "cardano_poe verify corpus size");
    for v in vs {
        let name = s(&v["name"]);
        let expected_signer_key = v
            .get("expected_signer_key_hex")
            .and_then(Value::as_str)
            .map(h);
        let result = cose_sign1_label309_verify(
            &h(s(&v["message_hex"])),
            &h(s(&v["detached_record_body_cbor_hex"])),
            expected_signer_key.as_deref(),
        );
        assert_verify_result(&result, &v["expected_result"], name);
    }
}

#[test]
fn cose_sign1_strict_ed25519_low_order_within_cose() {
    let corpus = load("cose/sign1-strict-ed25519.json");
    let vs = vectors(&corpus, "vectors");
    assert!(!vs.is_empty(), "strict-ed25519 corpus non-empty");
    for v in vs {
        let name = s(&v["name"]);
        // This message embeds a detached-style RFC 9052 Sig_structure whose body
        // is the C2SP low-order-A vector. Verify it via the general path with the
        // protected-header alg and the attached payload re-derivation; the only
        // thing under test is that strict Ed25519 REJECTS the low-order key.
        let message = h(s(&v["message_hex"]));
        let result = verify_general(&serde_json::json!({
            "message_hex": s(&v["message_hex"]),
            "external_aad_hex": s(&v["external_aad_hex"]),
        }));
        // The strict path must reject (SIGNATURE_INVALID). The fixture pins the
        // expected code directly.
        let expected = &v["expected_result"];
        assert_verify_result(&result, expected, name);
        // Independent direct check: the embedded Sig_structure IS `message`, so a
        // strict verify of the low-order key over it must be false.
        // (message itself is the Sig_structure for the embedded case.)
        let pk = [0u8; 32];
        let sig = h("36684ea91032ba5b1dbab2d02f4debc74c3327f2b3802e2e4d371aa42b12b56b05ba9a796274d80437afa36f1236563f2f3b0aa84cecddc3d20914615ba4fe02");
        assert!(
            !ed25519_verify(&pk, &message, &sig),
            "{name}: strict verify of low-order key is false"
        );
    }
}

#[test]
fn cose_sign1_label309_verify_rejects_mutated_body() {
    let corpus = load("cose/sign1-build.json");
    for v in vectors(&corpus, "cardano_poe_vectors") {
        let name = s(&v["name"]);
        let mut body = h(s(&v["record_body_cbor_hex"]));
        let last = body.len() - 1;
        body[last] ^= 0xff;
        let result = cose_sign1_label309_verify(&h(s(&v["expected_cose_sign1_hex"])), &body, None);
        match result {
            CoseVerifyResult::Err(code) => {
                assert_eq!(code.code(), "SIGNATURE_INVALID", "{name}");
            }
            CoseVerifyResult::Ok { .. } => panic!("{name}: mutated body must reject"),
        }
    }
}

// ---------------------------------------------------------------------------
// Detached + empty-protected + decode stability
// ---------------------------------------------------------------------------

#[test]
fn empty_protected_header_serializes_as_single_0x40() {
    let cose = encode_cose_sign1(&CoseHeader::new(), &CoseHeader::new(), None, &[7u8; 64]).unwrap();
    // 0x84 array(4), then 0x40 zero-length bstr for the protected element.
    assert_eq!(cose[0], 0x84);
    assert_eq!(cose[1], 0x40);
    // The decoder accepts 0x40 and yields an empty protected header.
    let decoded = decode_cose_sign1(&cose).unwrap();
    assert!(decoded.protected_header.is_empty());
    assert!(decoded.protected_bytes.is_empty());
    assert!(decoded.payload.is_none());
}

#[test]
fn empty_protected_header_as_wrapped_empty_map_is_rejected() {
    // Hand-build a COSE_Sign1 whose protected element is 0x41 0xA0 (a 1-byte
    // bstr wrapping an empty map). The decoder MUST reject it: empty protected
    // header must be the zero-length bstr 0x40.
    let cose = CborValue::Array(vec![
        CborValue::bytes(vec![0xa0]), // bstr wrapping an empty map
        CborValue::Map(vec![]),
        CborValue::Null,
        CborValue::bytes(vec![0u8; 64]),
    ]);
    let bytes = encode_canonical_cbor(&cose).unwrap();
    assert!(decode_cose_sign1(&bytes).is_err());
}

#[test]
fn detached_round_trips_and_decode_is_byte_stable() {
    let corpus = load("cose/sign1-build.json");
    for v in vectors(&corpus, "cardano_poe_vectors") {
        let name = s(&v["name"]);
        let cose = h(s(&v["expected_cose_sign1_hex"]));
        let decoded = decode_cose_sign1(&cose).unwrap();
        // Label 309 records carry a detached (null) payload.
        assert!(decoded.payload.is_none(), "{name}: payload is detached");
        // The protected header decodes to {1:-8, 4:<32B>}; re-encoding the whole
        // COSE_Sign1 from the decoded parts reproduces the original bytes.
        let re = encode_cose_sign1(
            &decoded.protected_header,
            &decoded.unprotected_header,
            None,
            &decoded.signature,
        )
        .unwrap();
        assert_eq!(
            hex::encode(&re),
            s(&v["expected_cose_sign1_hex"]),
            "{name}: re-encode stable"
        );
    }
}

#[test]
fn decode_rejects_non_four_element_array() {
    // 0x82 0x01 0x02 = [1, 2] — the reference's malformed-wire vector.
    assert!(decode_cose_sign1(&h("820102")).is_err());
}

// ---------------------------------------------------------------------------
// CIP-8 hashed mode (reproduced from the reference inline test)
// ---------------------------------------------------------------------------

/// Build a hashed-mode COSE_Sign1: `Sig_structure[3] = BLAKE2b-224(to_sign)`,
/// unprotected header `{"hashed": true}`, detached payload.
fn build_hashed_mode_cose(pubkey: &[u8], seed: &[u8; 32], record_body_cbor: &[u8]) -> Vec<u8> {
    let protected = protected_header_with_kid(pubkey);
    let protected_bytes = encode_canonical_cbor(&protected.to_cbor()).unwrap();
    let mut to_sign = CARDANO_POE_SIG_DOMAIN_PREFIX.as_bytes().to_vec();
    to_sign.extend_from_slice(record_body_cbor);
    let digest = blake2b224_test(&to_sign);
    let sig_structure = build_sig_structure(&protected_bytes, &[], &digest);
    let signature = ed25519_sign(seed, &sig_structure);
    let unprotected = CoseHeader::new().with_text("hashed", CborValue::Bool(true));
    encode_cose_sign1(&protected, &unprotected, None, &signature).unwrap()
}

/// Local 28-byte parameterized BLAKE2b for the test oracle (matches Python's
/// `hashlib.blake2b(..., digest_size=28)`).
fn blake2b224_test(input: &[u8]) -> [u8; 28] {
    use blake2::digest::consts::U28;
    use blake2::digest::Digest;
    use blake2::Blake2b;
    Blake2b::<U28>::digest(input).into()
}

#[test]
fn hashed_mode_accept_and_negatives() {
    let corpus = load("cose/sign1-build.json");
    for v in vectors(&corpus, "cardano_poe_vectors") {
        let name = s(&v["name"]);
        let pubkey = h(s(&v["signer_public_key_hex"]));
        let seed = seed32(s(&v["signer_secret_key_hex"]));
        let body = h(s(&v["record_body_cbor_hex"]));

        // Accept a valid hashed-mode COSE_Sign1.
        let hashed_cose = build_hashed_mode_cose(&pubkey, &seed, &body);
        let ok = cose_sign1_label309_verify(&hashed_cose, &body, None);
        assert!(ok.is_ok(), "{name}: valid hashed-mode accepted");

        // Reject when the "hashed" flag is stripped (verifier then expects the
        // un-hashed to_sign, so the signature no longer matches).
        let mut to_sign = CARDANO_POE_SIG_DOMAIN_PREFIX.as_bytes().to_vec();
        to_sign.extend_from_slice(&body);
        let digest = blake2b224_test(&to_sign);
        let protected = protected_header_with_kid(&pubkey);
        let protected_bytes = encode_canonical_cbor(&protected.to_cbor()).unwrap();
        let sig_structure = build_sig_structure(&protected_bytes, &[], &digest);
        let signature = ed25519_sign(&seed, &sig_structure);
        let stripped = encode_cose_sign1(&protected, &CoseHeader::new(), None, &signature).unwrap();
        let res = cose_sign1_label309_verify(&stripped, &body, None);
        match res {
            CoseVerifyResult::Err(code) => {
                assert_eq!(code.code(), "SIGNATURE_INVALID", "{name}: flag stripped");
            }
            CoseVerifyResult::Ok { .. } => panic!("{name}: stripped flag must reject"),
        }

        // Reject a bogus signature under the hashed flag.
        let bogus = encode_cose_sign1(
            &protected,
            &CoseHeader::new().with_text("hashed", CborValue::Bool(true)),
            None,
            &[0xab; 64],
        )
        .unwrap();
        let res = cose_sign1_label309_verify(&bogus, &body, None);
        assert!(!res.is_ok(), "{name}: bogus hashed signature rejected");

        // Non-hashed path remains accepted unchanged.
        let plain = cose_sign1_label309_build(
            &protected,
            &CoseHeader::new(),
            &body,
            Label309Signer::Seed(&seed),
        )
        .unwrap();
        assert!(
            cose_sign1_label309_verify(&plain, &body, None).is_ok(),
            "{name}: non-hashed path unchanged"
        );
    }
}

// ---------------------------------------------------------------------------
// Integer header labels outside the i64 range
// ---------------------------------------------------------------------------

/// A COSE_Sign1 whose protected header carries an integer label outside the
/// `i64` range MUST verify exactly as TypeScript and Python do. A CBOR integer
/// spans `-2^64 ..= 2^64 - 1`, so an unsigned `2^63` label or a negative
/// `-(2^63) - 1` label is well-formed; the `alg`/`kid` lookups consult only the
/// small labels `1`/`4`, so a large unknown label is verdict-neutral. The
/// expected `cose_hex` and `protected_bytes_hex` below were produced by the
/// Python reference SDK over the same seed/body; both implementations return a
/// VALID verdict with the identical signer key.
#[test]
fn integer_header_label_beyond_i64_range_verifies_like_the_reference() {
    let seed = seed32("1111111111111111111111111111111111111111111111111111111111111111");
    let pubkey = ed25519_public_key_from_seed(&seed);
    assert_eq!(
        hex::encode(&pubkey),
        "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
    );
    let body = h("a16161182a");

    // Build the protected header map directly so the out-of-range label can be
    // expressed as a raw CBOR integer (the typed `with_int` setter only emits
    // the small labels the SDK actually produces). The header is `{1: -8,
    // 4: <pub>, <big_label>: 0}` for each big_label below.
    struct Case {
        big_label: CborValue,
        expected_protected_bytes_hex: &'static str,
        expected_cose_hex: &'static str,
    }
    let cases = [
        // Unsigned 2^63 (just past i64::MAX): CBOR `1b8000000000000000`.
        Case {
            big_label: CborValue::Unsigned(1u64 << 63),
            expected_protected_bytes_hex:
                "a30127045820d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787371b800000000000000000",
            expected_cose_hex:
                "845830a30127045820d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787371b800000000000000000a0f658403a033014b6f56601d3dee2efc11e8e83f49bd128d0ca562c72dc7424be1685f985428ab64bb246839361cad7e8c6a204b4c197afe3581309a35c9e75ee041204",
        },
        // Negative -(2^63) - 1 (just past i64::MIN): -1 - m with m = 2^63, so
        // CBOR `3b8000000000000000`.
        Case {
            big_label: CborValue::Negative(1u64 << 63),
            expected_protected_bytes_hex:
                "a30127045820d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787373b800000000000000000",
            expected_cose_hex:
                "845830a30127045820d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787373b800000000000000000a0f658401476d5d46108513cf38031a0b08545068124440a13e4c050704f629190f88342a590bdcca346b4b4f848fece87a9a3b3e4e47fd89e05a9ec745ba385dcac9304",
        },
    ];

    for case in cases {
        let protected_map = CborValue::Map(vec![
            (CborValue::int(1), CborValue::int(-8)),
            (CborValue::int(4), CborValue::bytes(pubkey.to_vec())),
            (case.big_label, CborValue::int(0)),
        ]);
        let protected_bytes = encode_canonical_cbor(&protected_map).unwrap();
        assert_eq!(
            hex::encode(&protected_bytes),
            case.expected_protected_bytes_hex,
            "protected header bytes match the reference"
        );

        // Sign the Label 309 Sig_structure over the verbatim protected bytes, then
        // assemble the detached-payload COSE_Sign1 the same way the reference does.
        let sig_structure = build_label309_sig_structure(&protected_bytes, &body);
        let signature = ed25519_sign(&seed, &sig_structure);
        let cose = CborValue::Array(vec![
            CborValue::bytes(protected_bytes.clone()),
            CborValue::Map(vec![]),
            CborValue::Null,
            CborValue::bytes(signature.to_vec()),
        ]);
        let cose_bytes = encode_canonical_cbor(&cose).unwrap();
        assert_eq!(
            hex::encode(&cose_bytes),
            case.expected_cose_hex,
            "assembled COSE_Sign1 matches the reference bytes"
        );

        // The out-of-range label must NOT collapse the decode to MALFORMED_SIG_COSE.
        // Both the round-tripped decoder and the full verifier must accept it.
        let decoded = decode_cose_sign1(&cose_bytes).expect("decode retains the large label");
        assert_eq!(decoded.protected_bytes, protected_bytes);
        assert_eq!(decoded.protected_header.alg(), Some(-8));
        assert_eq!(decoded.protected_header.kid(), Some(pubkey));

        let result = cose_sign1_label309_verify(&cose_bytes, &body, None);
        match result {
            CoseVerifyResult::Ok { signer_key, alg } => {
                assert_eq!(signer_key, pubkey, "signer key");
                assert_eq!(alg, -8, "alg");
            }
            CoseVerifyResult::Err(code) => {
                panic!("expected VALID, got {}", code.code());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// COSE_Key decoder (reproduced from the reference inline test)
// ---------------------------------------------------------------------------

fn build_cose_key(entries: &[(i64, CborValue)]) -> Vec<u8> {
    let map = CborValue::Map(
        entries
            .iter()
            .map(|(k, v)| (CborValue::int(*k), v.clone()))
            .collect(),
    );
    encode_canonical_cbor(&map).unwrap()
}

#[test]
fn parse_cose_key_ed25519_cases() {
    let pub_key = vec![0xab; 32];

    // Canonical OKP/Ed25519 with explicit alg.
    let blob = build_cose_key(&[
        (1, CborValue::int(1)),                  // kty: OKP
        (3, CborValue::int(-8)),                 // alg: EdDSA
        (-1, CborValue::int(6)),                 // crv: Ed25519
        (-2, CborValue::bytes(pub_key.clone())), // x
    ]);
    assert_eq!(parse_cose_key_ed25519(&blob), Some([0xab; 32]));

    // alg omitted is accepted.
    let blob = build_cose_key(&[
        (1, CborValue::int(1)),
        (-1, CborValue::int(6)),
        (-2, CborValue::bytes(pub_key.clone())),
    ]);
    assert_eq!(parse_cose_key_ed25519(&blob), Some([0xab; 32]));

    // Wrong kty (EC2=2).
    let blob = build_cose_key(&[
        (1, CborValue::int(2)),
        (3, CborValue::int(-8)),
        (-1, CborValue::int(6)),
        (-2, CborValue::bytes(pub_key.clone())),
    ]);
    assert_eq!(parse_cose_key_ed25519(&blob), None);

    // Wrong crv (X25519=4).
    let blob = build_cose_key(&[
        (1, CborValue::int(1)),
        (3, CborValue::int(-8)),
        (-1, CborValue::int(4)),
        (-2, CborValue::bytes(pub_key.clone())),
    ]);
    assert_eq!(parse_cose_key_ed25519(&blob), None);

    // Wrong alg when present (ES256=-7).
    let blob = build_cose_key(&[
        (1, CborValue::int(1)),
        (3, CborValue::int(-7)),
        (-1, CborValue::int(6)),
        (-2, CborValue::bytes(pub_key.clone())),
    ]);
    assert_eq!(parse_cose_key_ed25519(&blob), None);

    // Missing x.
    let blob = build_cose_key(&[
        (1, CborValue::int(1)),
        (3, CborValue::int(-8)),
        (-1, CborValue::int(6)),
    ]);
    assert_eq!(parse_cose_key_ed25519(&blob), None);

    // Wrong x length (31 bytes).
    let blob = build_cose_key(&[
        (1, CborValue::int(1)),
        (3, CborValue::int(-8)),
        (-1, CborValue::int(6)),
        (-2, CborValue::bytes(vec![0xab; 31])),
    ]);
    assert_eq!(parse_cose_key_ed25519(&blob), None);

    // Garbage CBOR.
    assert_eq!(parse_cose_key_ed25519(&[0xff, 0xff, 0xff]), None);

    // Non-map (array).
    let blob = encode_canonical_cbor(&CborValue::Array(vec![
        CborValue::int(1),
        CborValue::int(2),
        CborValue::int(3),
    ]))
    .unwrap();
    assert_eq!(parse_cose_key_ed25519(&blob), None);
}
