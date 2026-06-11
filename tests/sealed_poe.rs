//! Byte-parity and behavioural tests for the sealed-PoE wrap / unwrap /
//! trial-decrypt layer.
//!
//! The fixture-driven cases replay the shared cross-implementation vectors
//! under `crypto-core/tests/fixtures/sealed-poe/`: the classical and hybrid
//! wrap KATs (expected slots, slots_mac, STREAM ciphertext — reproduced
//! byte-for-byte from the fixture-supplied randomness), the unwrap KATs and
//! negative cases, and the multi-priv trial-decrypt matrix. The behavioural
//! cases construct their envelopes in-test: the per-slot acceptance fold
//! (forged shadow slot), CEK-conflict rejection, honest recipient
//! duplication, low-order epk handling, bundle dispatch, the shuffle, and the
//! constant-time-across-slots loop accounting. Every assertion pins bytes,
//! plaintext, verdicts, or loop counts — never log strings.

mod common;

use std::collections::BTreeMap;

use cardanowall::hex;
use cardanowall::sealed_poe::{
    compute_slots_hash, ecies_sealed_poe_trial_decrypt, ecies_sealed_poe_unwrap,
    ecies_sealed_poe_wrap_with_rng, item_hashes_hash, slots_payload_key, stream_seal,
    Mlkem768X25519Slot, RecipientKeyBundle, SealedEnvelope, SealedKem, SealedPoeOutput,
    SealedSlots, TrialDecryptKeys, TrialDecryptResult, UnwrapFailureReason, UnwrapKeys,
    UnwrapProbe, UnwrapResult, WrapArgs, X25519Slot, AEAD_CHACHA20_POLY1305_STREAM64K,
    CARDANO_POE_HKDF_INFO_SLOTS_MAC, KEM_X25519,
};
use cardanowall::seed_derive::xwing_keygen;
use common::{crypto_core_fixtures, read_fixture_json};
use serde_json::Value;

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

fn fixture(name: &str) -> Value {
    read_fixture_json(&crypto_core_fixtures().join("sealed-poe").join(name))
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("field `{key}` must be a string: {v}"))
}

fn b(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(s(v, key)).unwrap_or_else(|e| panic!("bad hex in `{key}`: {e}"))
}

fn hex_list(v: &Value, key: &str) -> Vec<Vec<u8>> {
    v[key]
        .as_array()
        .unwrap_or_else(|| panic!("field `{key}` must be an array: {v}"))
        .iter()
        .map(|x| hex::decode(x.as_str().expect("hex string element")).expect("valid hex"))
        .collect()
}

/// The fixture's `hashes` object (algorithm identifier → digest hex): the
/// item's content-hash map the construction binds.
fn hashes_from(v: &Value) -> BTreeMap<String, Vec<u8>> {
    v["hashes"]
        .as_object()
        .unwrap_or_else(|| panic!("field `hashes` must be an object: {v}"))
        .iter()
        .map(|(alg, digest)| {
            (
                alg.clone(),
                hex::decode(digest.as_str().expect("hex digest")).expect("valid hex"),
            )
        })
        .collect()
}

/// A deterministic in-test hashes map for behavioural cases.
fn test_hashes() -> BTreeMap<String, Vec<u8>> {
    let mut map = BTreeMap::new();
    map.insert("sha2-256".to_string(), vec![0x5au8; 32]);
    map
}

/// A random source that refuses to be called — used everywhere a wrap is fully
/// deterministic (every secret supplied + `skip_shuffle`).
fn no_rng() -> impl FnMut(&mut [u8]) {
    |_: &mut [u8]| panic!("deterministic wrap must not draw randomness")
}

/// A simple counter-based pseudo-random fill for the property/shuffle tests,
/// where the exact bytes do not matter, only that distinct draws occur.
fn counter_rng(mut state: u64) -> impl FnMut(&mut [u8]) {
    move |buf: &mut [u8]| {
        for byte in buf.iter_mut() {
            // xorshift-ish step; quality is irrelevant, distinctness is enough.
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
    }
}

/// Deterministic 32-byte X25519 private key, matching the reference SDKs'
/// `make_priv(seed) = [(seed + i) & 0xff for i in 0..32]`.
fn make_priv(seed: u8) -> Vec<u8> {
    (0..32u16).map(|i| (u16::from(seed) + i) as u8).collect()
}

fn fill(byte: u8, n: usize) -> Vec<u8> {
    vec![byte; n]
}

/// Build a `SealedEnvelope` from a fixture JSON envelope (the
/// scheme/aead/kem/nonce_hex/slots/slots_mac_hex shape; hybrid slots carry a
/// single flat `kem_ct_hex`). Accepts arbitrary scheme / aead / kem values so
/// the negative vectors can be exercised.
fn envelope_from_json(env: &Value) -> SealedEnvelope {
    let scheme = env["scheme"].as_i64().expect("scheme must be an integer");
    let aead = s(env, "aead").to_string();
    let kem = s(env, "kem").to_string();
    let nonce = b(env, "nonce_hex");
    let slots_mac = b(env, "slots_mac_hex");
    let slot_values = env["slots"].as_array().expect("slots must be an array");

    // Route the slot shape on the envelope `kem`. For unknown KEMs the slot
    // array is still parsed as classical so the structure check can reject on
    // `kem` first (matching the reference, which validates kem before slots).
    let slots = if kem == "mlkem768x25519" {
        SealedSlots::Mlkem768X25519(
            slot_values
                .iter()
                .map(|sv| Mlkem768X25519Slot {
                    kem_ct: b(sv, "kem_ct_hex"),
                    wrap: b(sv, "wrap_hex"),
                })
                .collect(),
        )
    } else {
        SealedSlots::X25519(
            slot_values
                .iter()
                .map(|sv| X25519Slot {
                    epk: b(sv, "epk_hex"),
                    wrap: b(sv, "wrap_hex"),
                })
                .collect(),
        )
    };

    SealedEnvelope {
        scheme,
        aead,
        kem,
        nonce,
        slots,
        slots_mac,
    }
}

/// Recompute the `slots_mac` exactly as the producer does, for tests that
/// splice slot sets in-test.
fn reference_slots_mac(cek: &[u8], slots_hash: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    let hmac_key =
        cardanowall::kdf::hkdf_sha256(cek, &[], CARDANO_POE_HKDF_INFO_SLOTS_MAC, 32).expect("hkdf");
    let mut mac = <Hmac<Sha256>>::new_from_slice(&hmac_key).expect("hmac key");
    mac.update(slots_hash);
    mac.finalize().into_bytes().to_vec()
}

// --------------------------------------------------------------------------
// Classical wrap KATs (fixture-driven)
// --------------------------------------------------------------------------

/// Reproduce a classical wrap vector and pin every output byte.
fn check_wrap_positive(filename: &str) {
    let corpus = fixture(filename);
    let v = &corpus["vector"];
    let recipient_publics = hex_list(v, "recipient_publics_hex");
    let ephemeral_secrets = hex_list(v, "ephemeral_secrets_hex");
    let cek = b(v, "cek_hex");
    let nonce = b(v, "nonce_hex");
    let plaintext = b(v, "plaintext_hex");
    let hashes = hashes_from(v);

    let out = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: &plaintext,
            recipient_public_keys: &recipient_publics,
            hashes: &hashes,
            kem: Some(SealedKem::X25519),
            cek: Some(&cek),
            nonce: Some(&nonce),
            ephemeral_secrets: Some(&ephemeral_secrets),
            eseeds: None,
            skip_shuffle: true,
        },
        &mut no_rng(),
    )
    .unwrap_or_else(|e| panic!("{filename}: wrap failed: {e}"));

    assert_eq!(out.envelope.scheme, 1, "{filename}");
    assert_eq!(
        out.envelope.aead, AEAD_CHACHA20_POLY1305_STREAM64K,
        "{filename}"
    );
    assert_eq!(out.envelope.kem, "x25519", "{filename}");
    assert_eq!(
        hex::encode(&out.envelope.nonce),
        s(v, "nonce_hex"),
        "{filename}"
    );

    let expected_slots = v["expected_slots"].as_array().expect("expected_slots");
    let SealedSlots::X25519(slots) = &out.envelope.slots else {
        panic!("{filename}: expected classical slots");
    };
    assert_eq!(slots.len(), expected_slots.len(), "{filename} slot count");
    for (i, slot) in slots.iter().enumerate() {
        assert_eq!(
            hex::encode(&slot.epk),
            s(&expected_slots[i], "epk_hex"),
            "{filename} slot {i} epk"
        );
        assert_eq!(
            hex::encode(&slot.wrap),
            s(&expected_slots[i], "wrap_hex"),
            "{filename} slot {i} wrap"
        );
    }
    assert_eq!(
        hex::encode(&out.envelope.slots_mac),
        s(v, "expected_slots_mac_hex"),
        "{filename} slots_mac"
    );
    assert_eq!(
        hex::encode(&out.ciphertext),
        s(v, "expected_ciphertext_hex"),
        "{filename} ciphertext"
    );
}

#[test]
fn wrap_n1_empty() {
    check_wrap_positive("wrap-n1-empty.json");
}

#[test]
fn wrap_n3() {
    check_wrap_positive("wrap-n3.json");
}

#[test]
fn wrap_n32() {
    check_wrap_positive("wrap-n32.json");
}

// Wrap-input validation errors are construction-only codes whose calling
// conventions differ per SDK, so they are pinned with direct cases here rather
// than a shared byte corpus. Each case supplies an otherwise-valid input set
// and breaks exactly one argument. Cases that omit the cek/nonce override draw
// them from the rng before reaching the failing validation, so the rng is live.
#[test]
fn wrap_input_validation_codes() {
    let hashes = test_hashes();
    let valid_pub = fill(0x42, 32);

    struct Case {
        name: &'static str,
        recipients: Vec<Vec<u8>>,
        cek: Option<Vec<u8>>,
        nonce: Option<Vec<u8>>,
        ephemeral_secrets: Option<Vec<Vec<u8>>>,
        eseeds: Option<Vec<Vec<u8>>>,
        empty_hashes: bool,
        expected: &'static str,
    }
    let base = || Case {
        name: "",
        recipients: vec![valid_pub.clone()],
        cek: None,
        nonce: None,
        ephemeral_secrets: None,
        eseeds: None,
        empty_hashes: false,
        expected: "",
    };

    let cases = [
        Case {
            name: "zero recipients",
            recipients: vec![],
            expected: "ENC_SLOTS_EMPTY",
            ..base()
        },
        Case {
            name: "31-byte recipient public key",
            recipients: vec![fill(0x42, 31)],
            expected: "KEM_EPK_LENGTH_MISMATCH",
            ..base()
        },
        Case {
            name: "31-byte cek",
            cek: Some(fill(0x01, 31)),
            expected: "INVALID_CEK_LENGTH",
            ..base()
        },
        Case {
            name: "23-byte nonce",
            nonce: Some(fill(0x01, 23)),
            expected: "NONCE_LENGTH_MISMATCH",
            ..base()
        },
        Case {
            name: "31-byte ephemeral secret",
            ephemeral_secrets: Some(vec![fill(0x01, 31)]),
            expected: "INVALID_EPHEMERAL_SECRET_LENGTH",
            ..base()
        },
        Case {
            name: "ephemeral-secret count mismatch",
            ephemeral_secrets: Some(vec![fill(0x01, 32), fill(0x02, 32)]),
            expected: "EPHEMERAL_SECRETS_COUNT_MISMATCH",
            ..base()
        },
        Case {
            name: "eseeds supplied for the x25519 path",
            eseeds: Some(vec![fill(0x01, 64)]),
            expected: "EPHEMERAL_SECRETS_COUNT_MISMATCH",
            ..base()
        },
        Case {
            name: "empty hashes map",
            empty_hashes: true,
            expected: "ENC_REQUIRES_CONTENT_HASH",
            ..base()
        },
    ];

    let empty_hashes: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for case in &cases {
        let err = ecies_sealed_poe_wrap_with_rng(
            WrapArgs {
                plaintext: b"wrap validation",
                recipient_public_keys: &case.recipients,
                hashes: if case.empty_hashes {
                    &empty_hashes
                } else {
                    &hashes
                },
                kem: Some(SealedKem::X25519),
                cek: case.cek.as_deref(),
                nonce: case.nonce.as_deref(),
                ephemeral_secrets: case.ephemeral_secrets.as_deref(),
                eseeds: case.eseeds.as_deref(),
                skip_shuffle: true,
            },
            &mut counter_rng(0x2222_3333),
        )
        .expect_err(case.name);
        assert_eq!(err.code(), case.expected, "negative case {}", case.name);
    }
}

// --------------------------------------------------------------------------
// Hybrid (X-Wing) wrap KATs (fixture-driven)
// --------------------------------------------------------------------------

fn check_hybrid_positive(filename: &str) {
    let corpus = fixture(filename);
    let v = &corpus["vector"];
    let recipient_publics = hex_list(v, "recipient_publics_hex");
    let eseeds = hex_list(v, "eseeds_hex");
    let cek = b(v, "cek_hex");
    let nonce = b(v, "nonce_hex");
    let plaintext = b(v, "plaintext_hex");
    let hashes = hashes_from(v);

    let out = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: &plaintext,
            recipient_public_keys: &recipient_publics,
            hashes: &hashes,
            kem: Some(SealedKem::Mlkem768X25519),
            cek: Some(&cek),
            nonce: Some(&nonce),
            ephemeral_secrets: None,
            eseeds: Some(&eseeds),
            skip_shuffle: true,
        },
        &mut no_rng(),
    )
    .unwrap_or_else(|e| panic!("{filename}: hybrid wrap failed: {e}"));

    assert_eq!(out.envelope.scheme, 1, "{filename}");
    assert_eq!(
        out.envelope.aead, AEAD_CHACHA20_POLY1305_STREAM64K,
        "{filename}"
    );
    assert_eq!(out.envelope.kem, "mlkem768x25519", "{filename}");
    assert_eq!(
        hex::encode(&out.envelope.nonce),
        s(v, "nonce_hex"),
        "{filename}"
    );

    let expected_slots = v["expected_slots"].as_array().expect("expected_slots");
    let SealedSlots::Mlkem768X25519(slots) = &out.envelope.slots else {
        panic!("{filename}: expected hybrid slots");
    };
    assert_eq!(slots.len(), expected_slots.len(), "{filename} slot count");
    for (i, slot) in slots.iter().enumerate() {
        assert_eq!(
            hex::encode(&slot.kem_ct),
            s(&expected_slots[i], "kem_ct_hex"),
            "{filename} slot {i} kem_ct"
        );
        assert_eq!(
            hex::encode(&slot.wrap),
            s(&expected_slots[i], "wrap_hex"),
            "{filename} slot {i} wrap"
        );
    }
    assert_eq!(
        hex::encode(&out.envelope.slots_mac),
        s(v, "expected_slots_mac_hex"),
        "{filename} slots_mac"
    );
    assert_eq!(
        hex::encode(&out.ciphertext),
        s(v, "expected_ciphertext_hex"),
        "{filename} ciphertext"
    );

    // Each recipient's X-Wing secret seed unwraps back to the plaintext.
    let expected_plaintext = b(v, "expected_plaintext_hex");
    for seed_hex in v["recipient_seeds_hex"].as_array().expect("seeds") {
        let seed = hex::decode(seed_hex.as_str().expect("hex")).expect("valid hex");
        let result = ecies_sealed_poe_unwrap(
            &out.envelope,
            &out.ciphertext,
            &hashes,
            UnwrapKeys::Single(&seed),
            None,
        )
        .expect("unwrap should not error");
        assert_eq!(
            result,
            UnwrapResult::Matched {
                plaintext: expected_plaintext.clone()
            },
            "{filename} hybrid unwrap with seed {seed_hex}"
        );
    }
}

#[test]
fn wrap_hybrid_n1() {
    check_hybrid_positive("wrap-hybrid-n1.json");
}

#[test]
fn wrap_hybrid_n3() {
    check_hybrid_positive("wrap-hybrid-n3.json");
}

#[test]
fn hybrid_unwrap_of_degenerate_kem_ct_is_a_clean_non_match_not_a_panic() {
    // Adversarial X-Wing slot: a `kem_ct` whose X25519 ciphertext tail (the last
    // 32 bytes of the 1120-byte enc) is all-zero — a degenerate small-order
    // point. The decapsulator is spec-correct *non-rejecting*: it derives a
    // DEFINED secret over that point rather than panicking. The slot is then no
    // longer the one the wrap produced, so the per-slot wrap AEAD / slots_mac
    // fold rejects it and the end-to-end unwrap returns a structured
    // WRONG_RECIPIENT_KEY non-match — never an error, never a panic, never the
    // plaintext. This pins the DoS-resistant behaviour end-to-end.
    let recipient_seed = [0x42u8; 32];
    let recipient_public = xwing_keygen(&recipient_seed).to_vec();
    let recipients = vec![recipient_public];
    let eseeds = vec![fill(0x07, 64)];
    let hashes = test_hashes();

    let out = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: b"degenerate-kem-ct regression",
            recipient_public_keys: &recipients,
            hashes: &hashes,
            kem: Some(SealedKem::Mlkem768X25519),
            cek: Some(&fill(0x11, 32)),
            nonce: Some(&fill(0x22, 24)),
            ephemeral_secrets: None,
            eseeds: Some(&eseeds),
            skip_shuffle: true,
        },
        &mut no_rng(),
    )
    .expect("hybrid wrap");

    // Sanity: the untampered envelope unwraps to the plaintext.
    let clean = ecies_sealed_poe_unwrap(
        &out.envelope,
        &out.ciphertext,
        &hashes,
        UnwrapKeys::Single(&recipient_seed),
        None,
    )
    .expect("clean unwrap");
    assert!(clean.matched(), "baseline envelope must unwrap");

    // Rebuild the envelope with slot 0's kem_ct X25519 tail zeroed out.
    let SealedSlots::Mlkem768X25519(slots) = &out.envelope.slots else {
        panic!("expected hybrid slots");
    };
    let mut enc = slots[0].kem_ct.clone();
    enc[1088..1120].copy_from_slice(&[0u8; 32]);
    assert_eq!(&enc[1088..1120], &[0u8; 32], "ct_x25519 tail is all-zero");
    let degenerate_slot = Mlkem768X25519Slot {
        kem_ct: enc,
        wrap: slots[0].wrap.clone(),
    };
    let mut tampered = out.envelope.clone();
    tampered.slots = SealedSlots::Mlkem768X25519(vec![degenerate_slot]);

    // Decapsulating the degenerate point must not panic, and the unwrap must be
    // a structured WRONG_RECIPIENT_KEY non-match (the recovered KEK no longer
    // unwraps the CEK).
    let result = ecies_sealed_poe_unwrap(
        &tampered,
        &out.ciphertext,
        &hashes,
        UnwrapKeys::Single(&recipient_seed),
        None,
    )
    .expect("degenerate kem_ct must be a structured non-match, not an error");
    let UnwrapResult::NotMatched { reason } = result else {
        panic!("degenerate kem_ct must NOT match");
    };
    assert_eq!(reason, UnwrapFailureReason::WrongRecipientKey);
}

// --------------------------------------------------------------------------
// Classical unwrap KATs (fixture-driven)
// --------------------------------------------------------------------------

fn check_unwrap_positive(filename: &str) {
    let corpus = fixture(filename);
    let v = &corpus["vector"];
    let envelope = envelope_from_json(&v["envelope"]);
    let ciphertext = b(v, "ciphertext_hex");
    let privs = hex_list(v, "recipient_secrets_hex");
    let expected = b(v, "expected_plaintext_hex");
    let hashes = hashes_from(v);

    for priv_key in &privs {
        let result = ecies_sealed_poe_unwrap(
            &envelope,
            &ciphertext,
            &hashes,
            UnwrapKeys::Single(priv_key),
            None,
        )
        .unwrap_or_else(|e| panic!("{filename}: unwrap errored: {e}"));
        assert_eq!(
            result,
            UnwrapResult::Matched {
                plaintext: expected.clone()
            },
            "{filename}"
        );
    }
}

#[test]
fn unwrap_n1_empty() {
    check_unwrap_positive("unwrap-n1-empty.json");
}

#[test]
fn unwrap_n3() {
    check_unwrap_positive("unwrap-n3.json");
}

#[test]
fn unwrap_n32() {
    check_unwrap_positive("unwrap-n32.json");
}

#[test]
fn unwrap_duplicate_recipient_decrypts() {
    // Positive: the same recipient public key in two slots (fresh distinct
    // ephemerals, same CEK) MUST decrypt normally — the CEK-conflict check
    // rejects only DIFFERENT recovered CEKs, never honest recipient padding.
    check_unwrap_positive("unwrap-duplicate-recipient.json");
}

#[test]
fn unwrap_shadow_slot_pinned_vector() {
    // Slot 0 wrap-opens under the recipient's key with an attacker-chosen CEK,
    // but that CEK does not reproduce slots_mac, so the per-slot acceptance
    // fold (kem_ok AND wrap_open_ok AND mac_ok) skips it and the honest slot 1
    // wins. Accepting a slot on wrap-open success alone is non-conformant.
    let corpus = fixture("unwrap-shadow-slot.json");
    let v = &corpus["vector"];
    check_unwrap_positive("unwrap-shadow-slot.json");

    let envelope = envelope_from_json(&v["envelope"]);
    let privs = hex_list(v, "recipient_secrets_hex");
    let hashes = hashes_from(v);
    let expected_slot = v["expected_matched_slot_idx"]
        .as_u64()
        .expect("expected_matched_slot_idx") as usize;
    let trial =
        ecies_sealed_poe_trial_decrypt(&envelope, &hashes, TrialDecryptKeys::Multi(&privs), None)
            .expect("trial decrypt");
    let TrialDecryptResult::Match { slot_idx, cek } = trial else {
        panic!("shadow-slot vector must match");
    };
    assert_eq!(slot_idx, expected_slot);
    assert_eq!(hex::encode(&cek), s(v, "honest_cek_hex"));
}

#[test]
fn unwrap_negative_matched_false_single_priv() {
    let corpus = fixture("unwrap-negative.json");
    for v in corpus["matched_false_vectors"]
        .as_array()
        .expect("matched_false")
    {
        // The multipriv-mac-fail vector consumes the multi-priv surface.
        if v.get("recipient_secret_hex").is_none() {
            continue;
        }
        let name = s(v, "name");
        let envelope = envelope_from_json(&v["envelope"]);
        let ciphertext = b(v, "ciphertext_hex");
        let priv_key = b(v, "recipient_secret_hex");
        let hashes = hashes_from(v);
        let result = ecies_sealed_poe_unwrap(
            &envelope,
            &ciphertext,
            &hashes,
            UnwrapKeys::Single(&priv_key),
            None,
        )
        .unwrap_or_else(|e| panic!("{name}: should be a structured non-match, not error: {e}"));
        let UnwrapResult::NotMatched { reason } = result else {
            panic!("{name}: expected NotMatched");
        };
        assert_eq!(reason.as_str(), s(v, "expected_reason"), "{name}");
    }
}

#[test]
fn unwrap_negative_raise_single_priv() {
    let corpus = fixture("unwrap-negative.json");
    let hashes = test_hashes();
    for v in corpus["raise_vectors"].as_array().expect("raise_vectors") {
        let name = s(v, "name");
        // Single-priv raise cases only.
        if v.get("recipient_secret_hex").is_none() || v.get("recipient_secret_keys_hex").is_some() {
            continue;
        }
        let envelope = envelope_from_json(&v["envelope"]);
        let ciphertext = b(v, "ciphertext_hex");
        let priv_key = b(v, "recipient_secret_hex");
        let vector_hashes = v.get("hashes").map(|_| hashes_from(v));
        let err = ecies_sealed_poe_unwrap(
            &envelope,
            &ciphertext,
            vector_hashes.as_ref().unwrap_or(&hashes),
            UnwrapKeys::Single(&priv_key),
            None,
        )
        .expect_err(name);
        assert_eq!(err.code(), s(v, "expected_error_code"), "{name}");
    }
}

#[test]
fn unwrap_negative_multipriv_mac_fail() {
    let corpus = fixture("unwrap-negative.json");
    let v = corpus["matched_false_vectors"]
        .as_array()
        .expect("matched_false")
        .iter()
        .find(|x| s(x, "name") == "multipriv-mac-fail")
        .expect("multipriv-mac-fail vector");
    let envelope = envelope_from_json(&v["envelope"]);
    let ciphertext = b(v, "ciphertext_hex");
    let privs = hex_list(v, "recipient_secret_keys_hex");
    let hashes = hashes_from(v);
    let result = ecies_sealed_poe_unwrap(
        &envelope,
        &ciphertext,
        &hashes,
        UnwrapKeys::Multi(&privs),
        None,
    )
    .expect("structured non-match");
    assert_eq!(
        result,
        UnwrapResult::NotMatched {
            reason: UnwrapFailureReason::TamperedHeader
        }
    );
}

#[test]
fn unwrap_negative_multipriv_input_validation() {
    let corpus = fixture("unwrap-negative.json");
    let hashes = test_hashes();
    // empty / both-forms / neither-form / wrong-length all map to
    // INVALID_RECIPIENT_KEY in the reference; reproduce the ones the typed
    // Rust API can express via the multi-priv list.
    let v = corpus["raise_vectors"]
        .as_array()
        .expect("raise_vectors")
        .iter()
        .find(|x| s(x, "name") == "multipriv-element-wrong-length")
        .expect("multipriv-element-wrong-length");
    let envelope = envelope_from_json(&v["envelope"]);
    let ciphertext = b(v, "ciphertext_hex");
    let privs = hex_list(v, "recipient_secret_keys_hex");
    let err = ecies_sealed_poe_unwrap(
        &envelope,
        &ciphertext,
        &hashes,
        UnwrapKeys::Multi(&privs),
        None,
    )
    .expect_err("wrong-length element");
    assert_eq!(err.code(), "INVALID_RECIPIENT_KEY");

    // Empty flat list is a programmer error.
    let any = corpus["matched_false_vectors"].as_array().unwrap()[0].clone();
    let envelope = envelope_from_json(&any["envelope"]);
    let ciphertext = b(&any, "ciphertext_hex");
    let empty: Vec<Vec<u8>> = Vec::new();
    let err = ecies_sealed_poe_unwrap(
        &envelope,
        &ciphertext,
        &hashes,
        UnwrapKeys::Multi(&empty),
        None,
    )
    .expect_err("empty flat list");
    assert_eq!(err.code(), "INVALID_RECIPIENT_KEY");
}

// --------------------------------------------------------------------------
// Per-slot acceptance fold (in-test constructions)
// --------------------------------------------------------------------------

/// Extract the single X25519 slot from a one-recipient wrap output.
fn single_x25519_slot(out: &SealedPoeOutput) -> X25519Slot {
    match &out.envelope.slots {
        SealedSlots::X25519(slots) => slots[0].clone(),
        SealedSlots::Mlkem768X25519(_) => panic!("expected an x25519 wrap output"),
    }
}

/// Wrap one slot addressed to `recipient_priv` carrying `cek`, with a fixed
/// ephemeral, under a fixed nonce. Building block for spliced slot sets.
fn one_slot_for(recipient_priv: &[u8], cek: &[u8], nonce: &[u8], eph: u8) -> X25519Slot {
    let pub_keys = vec![cardanowall::sealed_poe::x25519_public_key(recipient_priv)
        .expect("derive recipient public key")
        .to_vec()];
    let hashes = test_hashes();
    let out = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: b"x",
            recipient_public_keys: &pub_keys,
            hashes: &hashes,
            kem: None,
            cek: Some(cek),
            nonce: Some(nonce),
            ephemeral_secrets: Some(&[fill(eph, 32)]),
            eseeds: None,
            skip_shuffle: true,
        },
        &mut no_rng(),
    )
    .expect("wrap one slot");
    single_x25519_slot(&out)
}

/// Build a spliced 2-slot envelope plus a ciphertext keyed to `honest_cek`:
/// the slots_mac and the STREAM ciphertext are both recomputed for the spliced
/// slot set under `honest_cek`.
fn spliced_envelope(
    slots: Vec<X25519Slot>,
    nonce: Vec<u8>,
    honest_cek: &[u8],
    plaintext: &[u8],
    hashes: &BTreeMap<String, Vec<u8>>,
) -> (SealedEnvelope, Vec<u8>) {
    let slots = SealedSlots::X25519(slots);
    let hashes_hash = item_hashes_hash(hashes).expect("hashes");
    let slots_hash = compute_slots_hash(
        AEAD_CHACHA20_POLY1305_STREAM64K,
        KEM_X25519,
        &nonce,
        &slots,
        &hashes_hash,
    );
    let slots_mac = reference_slots_mac(honest_cek, &slots_hash);
    let payload_key = slots_payload_key(honest_cek, &nonce);
    let ciphertext = stream_seal(&payload_key, plaintext);
    (
        SealedEnvelope {
            scheme: 1,
            aead: AEAD_CHACHA20_POLY1305_STREAM64K.to_string(),
            kem: KEM_X25519.to_string(),
            nonce,
            slots,
            slots_mac,
        },
        ciphertext,
    )
}

#[test]
fn forged_shadow_slot_before_the_honest_slot_still_decrypts_under_the_honest_cek() {
    // A malicious co-sender (or relay) plants a slot that wrap-opens under the
    // recipient's key with an ATTACKER CEK, positioned BEFORE the honest slot.
    // Because acceptance folds the slot-set MAC per slot, the forged slot's
    // CEK fails `slots_mac` and is skipped like a non-match; the honest slot
    // later in the array wins and the record decrypts under the honest CEK.
    let recipient_priv = make_priv(0xD0);
    let honest_cek = fill(0xAA, 32);
    let attacker_cek = fill(0xBB, 32);
    let nonce: Vec<u8> = (0..24u16).map(|i| (0xE0u16 + i) as u8).collect();
    let hashes = test_hashes();
    let plaintext = b"shadow-slot probe";

    let forged = one_slot_for(&recipient_priv, &attacker_cek, &nonce, 0x01);
    let honest = one_slot_for(&recipient_priv, &honest_cek, &nonce, 0x02);
    assert_ne!(forged.epk, honest.epk);

    // Shadow slot FIRST, honest slot second; MAC + ciphertext keyed to the
    // honest CEK over the spliced 2-slot set.
    let (envelope, ciphertext) =
        spliced_envelope(vec![forged, honest], nonce, &honest_cek, plaintext, &hashes);

    let mut probe = UnwrapProbe::default();
    let result = ecies_sealed_poe_unwrap(
        &envelope,
        &ciphertext,
        &hashes,
        UnwrapKeys::Single(&recipient_priv),
        Some(&mut probe),
    )
    .expect("structured result");
    assert_eq!(
        result,
        UnwrapResult::Matched {
            plaintext: plaintext.to_vec()
        },
        "the honest slot must win past the forged shadow slot"
    );
    // Constant-time-across-slots: both slots entered even though slot 1 wins.
    assert_eq!(probe.inner.count, 2);

    // Trial-decrypt selects the honest slot's index and CEK.
    let trial = ecies_sealed_poe_trial_decrypt(
        &envelope,
        &hashes,
        TrialDecryptKeys::Multi(std::slice::from_ref(&recipient_priv)),
        None,
    )
    .expect("trial decrypt");
    assert_eq!(
        trial,
        TrialDecryptResult::Match {
            slot_idx: 1,
            cek: honest_cek.clone()
        }
    );
}

#[test]
fn two_cek_splice_decrypts_under_the_mac_keyed_cek() {
    // Splice an envelope from two single-slot wraps that address the SAME
    // recipient but carry DIFFERENT CEKs, with slots_mac and ciphertext keyed
    // to the FIRST slot's CEK. Under the per-slot acceptance fold the second
    // slot wrap-opens but its CEK fails the MAC, so it is inert — the record
    // decrypts under the committed CEK and the CEK-conflict flag stays clear.
    // (Two ACCEPTED slots with different CEKs would need the MAC to verify
    // under both keys — the commitment collision the construction assumes
    // away — so the conflict rejection itself is defence-in-depth with no
    // honestly constructible vector.) Same-CEK recipient duplication, the
    // honest padding technique, is pinned as a clean match below.
    let recipient_priv = make_priv(0xD0);
    let cek_a = fill(0xAA, 32);
    let cek_b = fill(0xBB, 32);
    let nonce: Vec<u8> = (0..24u16).map(|i| (0xE0u16 + i) as u8).collect();
    let hashes = test_hashes();

    let slot0 = one_slot_for(&recipient_priv, &cek_a, &nonce, 0x01);
    let slot1 = one_slot_for(&recipient_priv, &cek_b, &nonce, 0x02);
    assert_ne!(slot0.epk, slot1.epk);

    let (envelope, ciphertext) = spliced_envelope(
        vec![slot0, slot1],
        nonce,
        &cek_a,
        b"conflict-probe",
        &hashes,
    );

    // Slot 1 wrap-opens with cek_b but fails the folded MAC → inert; slot 0 is
    // the only accepted slot and the record decrypts under cek_a.
    let single = ecies_sealed_poe_unwrap(
        &envelope,
        &ciphertext,
        &hashes,
        UnwrapKeys::Single(&recipient_priv),
        None,
    )
    .expect("structured result");
    assert_eq!(
        single,
        UnwrapResult::Matched {
            plaintext: b"conflict-probe".to_vec()
        }
    );

    // Same-CEK duplication (the honest padding technique) is a clean match and
    // never a conflict: two slots, fresh ephemerals, identical CEK.
    let dup0 = one_slot_for(&recipient_priv, &cek_a, &envelope.nonce, 0x03);
    let dup1 = one_slot_for(&recipient_priv, &cek_a, &envelope.nonce, 0x04);
    let (dup_env, dup_ct) = spliced_envelope(
        vec![dup0, dup1],
        envelope.nonce.clone(),
        &cek_a,
        b"dup-recipient",
        &hashes,
    );
    let trial = ecies_sealed_poe_trial_decrypt(
        &dup_env,
        &hashes,
        TrialDecryptKeys::Multi(std::slice::from_ref(&recipient_priv)),
        None,
    )
    .expect("trial decrypt");
    assert_eq!(
        trial,
        TrialDecryptResult::Match {
            slot_idx: 0,
            cek: cek_a.clone()
        },
        "both slots are accepted with the same CEK; the first wins, no conflict"
    );
    let dup_unwrap = ecies_sealed_poe_unwrap(
        &dup_env,
        &dup_ct,
        &hashes,
        UnwrapKeys::Single(&recipient_priv),
        None,
    )
    .expect("structured result");
    assert_eq!(
        dup_unwrap,
        UnwrapResult::Matched {
            plaintext: b"dup-recipient".to_vec()
        }
    );
}

#[test]
fn wrap_opened_but_no_acceptance_is_tampered_header() {
    // An honest single-slot envelope with its slots_mac flipped: the slot
    // still wrap-opens (kem_ok AND open_ok) but no candidate CEK reproduces
    // the MAC, so nothing is accepted → TAMPERED_HEADER, not
    // WRONG_RECIPIENT_KEY.
    let recipient_priv = fill(0x7a, 32);
    let recipient_pub = cardanowall::sealed_poe::x25519_public_key(&recipient_priv).unwrap();
    let hashes = test_hashes();
    let mut wrapped = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: &fill(0xab, 16),
            recipient_public_keys: &[recipient_pub.to_vec()],
            hashes: &hashes,
            cek: Some(&fill(0x33, 32)),
            nonce: Some(&fill(0x44, 24)),
            ephemeral_secrets: Some(&[fill(0x55, 32)]),
            skip_shuffle: true,
            ..Default::default()
        },
        &mut no_rng(),
    )
    .expect("wrap");
    wrapped.envelope.slots_mac[0] ^= 0xff;

    let result = ecies_sealed_poe_unwrap(
        &wrapped.envelope,
        &wrapped.ciphertext,
        &hashes,
        UnwrapKeys::Single(&recipient_priv),
        None,
    )
    .expect("structured result");
    assert_eq!(
        result,
        UnwrapResult::NotMatched {
            reason: UnwrapFailureReason::TamperedHeader
        }
    );

    // Trial-decrypt reduces every non-acceptance to NoMatch.
    let trial = ecies_sealed_poe_trial_decrypt(
        &wrapped.envelope,
        &hashes,
        TrialDecryptKeys::Multi(&[recipient_priv]),
        None,
    )
    .expect("trial decrypt");
    assert_eq!(trial, TrialDecryptResult::NoMatch);
}

#[test]
fn hashes_splice_is_rejected_on_chain_side() {
    // An honest envelope paired with an item whose `hashes` map differs from
    // the one it was sealed for: the transcript's hashes_hash differs, the
    // accepted slot's MAC check fails, and the record is rejected BEFORE any
    // ciphertext work — the slot still wrap-opens, so the typed reason is the
    // tampered-header class.
    let recipient_priv = fill(0x7a, 32);
    let recipient_pub = cardanowall::sealed_poe::x25519_public_key(&recipient_priv).unwrap();
    let sealed_hashes = test_hashes();
    let wrapped = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: b"hashes-splice probe",
            recipient_public_keys: &[recipient_pub.to_vec()],
            hashes: &sealed_hashes,
            cek: Some(&fill(0x33, 32)),
            nonce: Some(&fill(0x44, 24)),
            ephemeral_secrets: Some(&[fill(0x55, 32)]),
            skip_shuffle: true,
            ..Default::default()
        },
        &mut no_rng(),
    )
    .expect("wrap");

    // Sanity: with the sealed hashes the record decrypts.
    let clean = ecies_sealed_poe_unwrap(
        &wrapped.envelope,
        &wrapped.ciphertext,
        &sealed_hashes,
        UnwrapKeys::Single(&recipient_priv),
        None,
    )
    .expect("structured result");
    assert!(clean.matched());

    // Spliced item: a different digest under the same algorithm.
    let mut spliced_hashes = BTreeMap::new();
    spliced_hashes.insert("sha2-256".to_string(), vec![0xEEu8; 32]);
    let spliced = ecies_sealed_poe_unwrap(
        &wrapped.envelope,
        &wrapped.ciphertext,
        &spliced_hashes,
        UnwrapKeys::Single(&recipient_priv),
        None,
    )
    .expect("structured result");
    assert_eq!(
        spliced,
        UnwrapResult::NotMatched {
            reason: UnwrapFailureReason::TamperedHeader
        }
    );

    let trial = ecies_sealed_poe_trial_decrypt(
        &wrapped.envelope,
        &spliced_hashes,
        TrialDecryptKeys::Multi(&[recipient_priv]),
        None,
    )
    .expect("trial decrypt");
    assert_eq!(trial, TrialDecryptResult::NoMatch);
}

#[test]
fn tampered_stream_ciphertext_is_tampered_ciphertext() {
    // CEK accepted, MAC verified, but the STREAM blob fails: TAMPERED_CIPHERTEXT.
    let recipient_priv = fill(0x7a, 32);
    let recipient_pub = cardanowall::sealed_poe::x25519_public_key(&recipient_priv).unwrap();
    let hashes = test_hashes();
    let wrapped = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: b"stream-tamper probe",
            recipient_public_keys: &[recipient_pub.to_vec()],
            hashes: &hashes,
            cek: Some(&fill(0x33, 32)),
            nonce: Some(&fill(0x44, 24)),
            ephemeral_secrets: Some(&[fill(0x55, 32)]),
            skip_shuffle: true,
            ..Default::default()
        },
        &mut no_rng(),
    )
    .expect("wrap");

    // Flip a ciphertext byte, truncate, and append — all the same reason.
    let mut flipped = wrapped.ciphertext.clone();
    flipped[0] ^= 0x01;
    let truncated = wrapped.ciphertext[..wrapped.ciphertext.len() - 1].to_vec();
    let mut trailing = wrapped.ciphertext.clone();
    trailing.extend_from_slice(&[0u8; 16]);

    for (label, ct) in [
        ("flipped", &flipped),
        ("truncated", &truncated),
        ("trailing", &trailing),
    ] {
        let result = ecies_sealed_poe_unwrap(
            &wrapped.envelope,
            ct,
            &hashes,
            UnwrapKeys::Single(&recipient_priv),
            None,
        )
        .expect("structured result");
        assert_eq!(
            result,
            UnwrapResult::NotMatched {
                reason: UnwrapFailureReason::TamperedCiphertext
            },
            "{label}"
        );
    }
}

#[test]
fn large_payload_crosses_chunk_boundaries_end_to_end() {
    // A plaintext spanning three STREAM chunks roundtrips through the full
    // wrap/unwrap path.
    let recipient_priv = fill(0x7a, 32);
    let recipient_pub = cardanowall::sealed_poe::x25519_public_key(&recipient_priv).unwrap();
    let hashes = test_hashes();
    let plaintext: Vec<u8> = (0..(2 * 65536 + 12345)).map(|i| (i % 253) as u8).collect();
    let wrapped = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: &plaintext,
            recipient_public_keys: &[recipient_pub.to_vec()],
            hashes: &hashes,
            cek: Some(&fill(0x33, 32)),
            nonce: Some(&fill(0x44, 24)),
            ephemeral_secrets: Some(&[fill(0x55, 32)]),
            skip_shuffle: true,
            ..Default::default()
        },
        &mut no_rng(),
    )
    .expect("wrap");
    // 3 chunks → 3 tags.
    assert_eq!(wrapped.ciphertext.len(), plaintext.len() + 3 * 16);
    let result = ecies_sealed_poe_unwrap(
        &wrapped.envelope,
        &wrapped.ciphertext,
        &hashes,
        UnwrapKeys::Single(&recipient_priv),
        None,
    )
    .expect("structured result");
    assert_eq!(result, UnwrapResult::Matched { plaintext });
}

// --------------------------------------------------------------------------
// Multi-priv unwrap matrix (fixture-driven)
// --------------------------------------------------------------------------

struct MultiprivCase {
    envelope: SealedEnvelope,
    ciphertext: Vec<u8>,
    privs: Vec<Vec<u8>>,
    hashes: BTreeMap<String, Vec<u8>>,
    vector: Value,
}

fn load_multipriv(filename: &str) -> MultiprivCase {
    let corpus = fixture(filename);
    let v = corpus["vector"].clone();
    MultiprivCase {
        envelope: envelope_from_json(&v["envelope"]),
        ciphertext: b(&v, "ciphertext_hex"),
        privs: hex_list(&v, "recipient_privs_hex"),
        hashes: hashes_from(&v),
        vector: v,
    }
}

#[test]
fn unwrap_multipriv_current_match() {
    let c = load_multipriv("unwrap-multipriv-current-match.json");
    let mut probe = UnwrapProbe::default();
    let result = ecies_sealed_poe_unwrap(
        &c.envelope,
        &c.ciphertext,
        &c.hashes,
        UnwrapKeys::Multi(&c.privs),
        Some(&mut probe),
    )
    .expect("unwrap");
    assert_eq!(
        result,
        UnwrapResult::Matched {
            plaintext: b(&c.vector, "expected_plaintext_hex")
        }
    );
    assert_eq!(
        probe.outer.count as u64,
        c.vector["expected_outer_loop_count"].as_u64().unwrap()
    );
    let inner = c.vector["expected_inner_loop_count_per_priv"]
        .as_u64()
        .unwrap() as usize;
    assert_eq!(probe.inner.per_priv_counts, vec![inner]);
}

#[test]
fn unwrap_multipriv_archived_match() {
    let c = load_multipriv("unwrap-multipriv-archived-match.json");
    let mut probe = UnwrapProbe::default();
    let result = ecies_sealed_poe_unwrap(
        &c.envelope,
        &c.ciphertext,
        &c.hashes,
        UnwrapKeys::Multi(&c.privs),
        Some(&mut probe),
    )
    .expect("unwrap");
    assert_eq!(
        result,
        UnwrapResult::Matched {
            plaintext: b(&c.vector, "expected_plaintext_hex")
        }
    );
    assert_eq!(
        probe.outer.count as u64,
        c.vector["expected_outer_loop_count"].as_u64().unwrap()
    );
    let inner = c.vector["expected_inner_loop_count_per_priv"]
        .as_u64()
        .unwrap() as usize;
    assert_eq!(probe.inner.per_priv_counts, vec![inner, inner, inner]);
}

#[test]
fn unwrap_multipriv_no_match() {
    let c = load_multipriv("unwrap-multipriv-no-match.json");
    let mut probe = UnwrapProbe::default();
    let result = ecies_sealed_poe_unwrap(
        &c.envelope,
        &c.ciphertext,
        &c.hashes,
        UnwrapKeys::Multi(&c.privs),
        Some(&mut probe),
    )
    .expect("unwrap");
    assert_eq!(
        result,
        UnwrapResult::NotMatched {
            reason: UnwrapFailureReason::WrongRecipientKey
        }
    );
    assert_eq!(
        probe.outer.count as u64,
        c.vector["expected_outer_loop_count"].as_u64().unwrap()
    );
    let inner = c.vector["expected_inner_loop_count_per_priv"]
        .as_u64()
        .unwrap() as usize;
    assert_eq!(probe.inner.per_priv_counts, vec![inner; 4]);
}

#[test]
fn unwrap_multipriv_n32_k10_worst_case() {
    let c = load_multipriv("unwrap-multipriv-n32-k10-worst-case.json");
    let mut probe = UnwrapProbe::default();
    let result = ecies_sealed_poe_unwrap(
        &c.envelope,
        &c.ciphertext,
        &c.hashes,
        UnwrapKeys::Multi(&c.privs),
        Some(&mut probe),
    )
    .expect("unwrap");
    assert_eq!(
        result,
        UnwrapResult::Matched {
            plaintext: b(&c.vector, "expected_plaintext_hex")
        }
    );
    assert_eq!(probe.outer.count, 10);
    assert_eq!(probe.inner.per_priv_counts.len(), 10);
    assert!(probe.inner.per_priv_counts.iter().all(|&c| c == 32));
    assert_eq!(probe.inner.per_priv_counts.iter().sum::<usize>(), 320);
}

#[test]
fn unwrap_multipriv_constant_time_across_slots_matrix() {
    let scenarios: &[(&str, usize, usize, bool)] = &[
        ("unwrap-multipriv-ac9-priv0-slot0.json", 1, 1, true),
        ("unwrap-multipriv-ac9-priv0-slot31.json", 1, 1, true),
        ("unwrap-multipriv-ac9-priv4-slot0.json", 5, 5, true),
        ("unwrap-multipriv-ac9-priv4-slot31.json", 5, 5, true),
        ("unwrap-multipriv-ac9-no-match.json", 5, 5, false),
    ];
    for (filename, expected_outer, n_privs_entered, matched) in scenarios {
        let c = load_multipriv(filename);
        let mut probe = UnwrapProbe::default();
        let result = ecies_sealed_poe_unwrap(
            &c.envelope,
            &c.ciphertext,
            &c.hashes,
            UnwrapKeys::Multi(&c.privs),
            Some(&mut probe),
        )
        .expect("unwrap");
        if *matched {
            assert_eq!(
                result,
                UnwrapResult::Matched {
                    plaintext: b(&c.vector, "expected_plaintext_hex")
                },
                "{filename}"
            );
        } else {
            assert_eq!(
                result,
                UnwrapResult::NotMatched {
                    reason: UnwrapFailureReason::WrongRecipientKey
                },
                "{filename}"
            );
        }
        assert_eq!(probe.outer.count, *expected_outer, "{filename} outer");
        // Constant-time across slots: every entered priv ran all 32 slots.
        assert_eq!(
            probe.inner.per_priv_counts,
            vec![32usize; *n_privs_entered],
            "{filename} inner"
        );
    }
}

// --------------------------------------------------------------------------
// Trial-decrypt-only (no content access)
// --------------------------------------------------------------------------

#[test]
fn trial_decrypt_current_match_reports_slot_index() {
    let c = load_multipriv("unwrap-multipriv-current-match.json");
    let mut probe = UnwrapProbe::default();
    let res = ecies_sealed_poe_trial_decrypt(
        &c.envelope,
        &c.hashes,
        TrialDecryptKeys::Multi(&c.privs),
        Some(&mut probe),
    )
    .expect("trial decrypt");
    match res {
        TrialDecryptResult::Match { slot_idx, cek } => {
            assert_eq!(slot_idx, 0);
            assert_eq!(cek.len(), 32);
        }
        other => panic!("expected match, got {other:?}"),
    }
    assert_eq!(
        probe.outer.count as u64,
        c.vector["expected_outer_loop_count"].as_u64().unwrap()
    );
    assert_eq!(
        probe.inner.count as u64,
        c.vector["expected_inner_loop_count_per_priv"]
            .as_u64()
            .unwrap()
    );
}

#[test]
fn trial_decrypt_archived_match_constant_time_inner() {
    let c = load_multipriv("unwrap-multipriv-archived-match.json");
    let mut probe = UnwrapProbe::default();
    let res = ecies_sealed_poe_trial_decrypt(
        &c.envelope,
        &c.hashes,
        TrialDecryptKeys::Multi(&c.privs),
        Some(&mut probe),
    )
    .expect("trial decrypt");
    assert!(matches!(res, TrialDecryptResult::Match { .. }));
    assert_eq!(
        probe.outer.count as u64,
        c.vector["expected_outer_loop_count"].as_u64().unwrap()
    );
    let inner = c.vector["expected_inner_loop_count_per_priv"]
        .as_u64()
        .unwrap() as usize;
    assert_eq!(probe.inner.per_priv_counts, vec![inner, inner, inner]);
}

#[test]
fn trial_decrypt_no_match_exhausts_all_privs() {
    let c = load_multipriv("unwrap-multipriv-no-match.json");
    let mut probe = UnwrapProbe::default();
    let res = ecies_sealed_poe_trial_decrypt(
        &c.envelope,
        &c.hashes,
        TrialDecryptKeys::Multi(&c.privs),
        Some(&mut probe),
    )
    .expect("trial decrypt");
    assert_eq!(res, TrialDecryptResult::NoMatch);
    assert_eq!(
        probe.outer.count as u64,
        c.vector["expected_outer_loop_count"].as_u64().unwrap()
    );
}

#[test]
fn trial_decrypt_n32_k10_enters_320_slots() {
    let c = load_multipriv("unwrap-multipriv-n32-k10-worst-case.json");
    let mut probe = UnwrapProbe::default();
    let res = ecies_sealed_poe_trial_decrypt(
        &c.envelope,
        &c.hashes,
        TrialDecryptKeys::Multi(&c.privs),
        Some(&mut probe),
    )
    .expect("trial decrypt");
    assert!(matches!(res, TrialDecryptResult::Match { .. }));
    assert_eq!(probe.outer.count, 10);
    assert_eq!(probe.inner.per_priv_counts.len(), 10);
    assert!(probe.inner.per_priv_counts.iter().all(|&c| c == 32));
    assert_eq!(probe.inner.per_priv_counts.iter().sum::<usize>(), 320);
}

#[test]
fn trial_decrypt_rejects_empty_flat_list() {
    let c = load_multipriv("unwrap-multipriv-current-match.json");
    let empty: Vec<Vec<u8>> = Vec::new();
    let err = ecies_sealed_poe_trial_decrypt(
        &c.envelope,
        &c.hashes,
        TrialDecryptKeys::Multi(&empty),
        None,
    )
    .expect_err("empty flat list");
    assert_eq!(err.code(), "INVALID_RECIPIENT_KEY");
}

#[test]
fn trial_decrypt_partitioning_oracle_nonce_check() {
    let c = load_multipriv("unwrap-multipriv-current-match.json");
    let mut bad = c.envelope.clone();
    bad.nonce = vec![0u8; 20];
    let err =
        ecies_sealed_poe_trial_decrypt(&bad, &c.hashes, TrialDecryptKeys::Multi(&c.privs), None)
            .expect_err("bad nonce");
    assert_eq!(err.code(), "NONCE_LENGTH_MISMATCH");
}

// --------------------------------------------------------------------------
// Partitioning-oracle pre-check ordering (single-priv, in-test)
// --------------------------------------------------------------------------

#[test]
fn partitioning_oracle_pre_check_order() {
    let priv_key = make_priv(0xaa);
    let valid_epk = cardanowall::sealed_poe::x25519_public_key(&make_priv(0xbb)).unwrap();
    let valid_wrap = fill(0xcc, 48);
    let valid_nonce = vec![0u8; 24];
    let valid_mac = fill(0xdd, 32);
    let valid_ct = fill(0xee, 16);
    let hashes = test_hashes();

    let base = |slots: SealedSlots, nonce: Vec<u8>, mac: Vec<u8>| SealedEnvelope {
        scheme: 1,
        aead: AEAD_CHACHA20_POLY1305_STREAM64K.to_string(),
        kem: "x25519".to_string(),
        nonce,
        slots,
        slots_mac: mac,
    };

    // 1. empty slots
    let env = base(
        SealedSlots::X25519(vec![]),
        valid_nonce.clone(),
        valid_mac.clone(),
    );
    assert_eq!(
        ecies_sealed_poe_unwrap(
            &env,
            &valid_ct,
            &hashes,
            UnwrapKeys::Single(&priv_key),
            None
        )
        .unwrap_err()
        .code(),
        "ENC_SLOTS_EMPTY"
    );

    // 2. nonce wrong length
    let env = base(
        SealedSlots::X25519(vec![X25519Slot {
            epk: valid_epk.to_vec(),
            wrap: valid_wrap.clone(),
        }]),
        vec![0u8; 12],
        valid_mac.clone(),
    );
    assert_eq!(
        ecies_sealed_poe_unwrap(
            &env,
            &valid_ct,
            &hashes,
            UnwrapKeys::Single(&priv_key),
            None
        )
        .unwrap_err()
        .code(),
        "NONCE_LENGTH_MISMATCH"
    );

    // 3. slots_mac wrong length
    let env = base(
        SealedSlots::X25519(vec![X25519Slot {
            epk: valid_epk.to_vec(),
            wrap: valid_wrap.clone(),
        }]),
        valid_nonce.clone(),
        fill(0xdd, 16),
    );
    assert_eq!(
        ecies_sealed_poe_unwrap(
            &env,
            &valid_ct,
            &hashes,
            UnwrapKeys::Single(&priv_key),
            None
        )
        .unwrap_err()
        .code(),
        "ENC_SLOTS_MAC_INVALID_LENGTH"
    );

    // 4. epk wrong length
    let env = base(
        SealedSlots::X25519(vec![X25519Slot {
            epk: fill(0xbb, 16),
            wrap: valid_wrap.clone(),
        }]),
        valid_nonce.clone(),
        valid_mac.clone(),
    );
    assert_eq!(
        ecies_sealed_poe_unwrap(
            &env,
            &valid_ct,
            &hashes,
            UnwrapKeys::Single(&priv_key),
            None
        )
        .unwrap_err()
        .code(),
        "KEM_EPK_LENGTH_MISMATCH"
    );

    // 5. wrap wrong length
    let env = base(
        SealedSlots::X25519(vec![X25519Slot {
            epk: valid_epk.to_vec(),
            wrap: fill(0xcc, 32),
        }]),
        valid_nonce,
        valid_mac,
    );
    assert_eq!(
        ecies_sealed_poe_unwrap(
            &env,
            &valid_ct,
            &hashes,
            UnwrapKeys::Single(&priv_key),
            None
        )
        .unwrap_err()
        .code(),
        "WRAP_LENGTH_MISMATCH"
    );

    // 6. unsupported scheme / aead use the wire-registry strings
    let mut env = base(
        SealedSlots::X25519(vec![X25519Slot {
            epk: valid_epk.to_vec(),
            wrap: fill(0xcc, 48),
        }]),
        vec![0u8; 24],
        fill(0xdd, 32),
    );
    env.scheme = 2;
    assert_eq!(
        ecies_sealed_poe_unwrap(
            &env,
            &valid_ct,
            &hashes,
            UnwrapKeys::Single(&priv_key),
            None
        )
        .unwrap_err()
        .code(),
        "UNSUPPORTED_ENVELOPE_SCHEME"
    );
    env.scheme = 1;
    env.aead = "xchacha20-poly1305".to_string();
    assert_eq!(
        ecies_sealed_poe_unwrap(
            &env,
            &valid_ct,
            &hashes,
            UnwrapKeys::Single(&priv_key),
            None
        )
        .unwrap_err()
        .code(),
        "UNSUPPORTED_AEAD_ALG"
    );
}

// --------------------------------------------------------------------------
// Single-priv guard: multi-priv outer counter stays untouched (in-test)
// --------------------------------------------------------------------------

#[test]
fn single_priv_does_not_enter_the_multi_priv_outer_loop() {
    let privs: Vec<Vec<u8>> = (0..4u8).map(|i| make_priv(0x10 + i * 0x20)).collect();
    let pubs: Vec<Vec<u8>> = privs
        .iter()
        .map(|p| {
            cardanowall::sealed_poe::x25519_public_key(p)
                .unwrap()
                .to_vec()
        })
        .collect();
    let hashes = test_hashes();
    let out = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: b"single-priv probe",
            recipient_public_keys: &pubs,
            hashes: &hashes,
            skip_shuffle: true,
            ..Default::default()
        },
        &mut counter_rng(0x5151_2323),
    )
    .expect("wrap");

    let mut probe = UnwrapProbe::default();
    let result = ecies_sealed_poe_unwrap(
        &out.envelope,
        &out.ciphertext,
        &hashes,
        UnwrapKeys::Single(&privs[0]),
        Some(&mut probe),
    )
    .expect("unwrap");
    assert_eq!(
        result,
        UnwrapResult::Matched {
            plaintext: b"single-priv probe".to_vec()
        }
    );
    // Constant-time across slots: every slot entered.
    assert_eq!(probe.inner.count, 4);
    // The single-priv path must NOT enter the multi-priv outer loop.
    assert_eq!(probe.outer.count, 0);
}

// --------------------------------------------------------------------------
// Low-order epk: a non-match, never a crash (in-test)
// --------------------------------------------------------------------------

const LOW_ORDER_EPKS: &[&str] = &[
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];

fn wrap_two_recipients(plaintext: &[u8], hashes: &BTreeMap<String, Vec<u8>>) -> SealedPoeOutput {
    let r0 = make_priv(0x20);
    let r1 = make_priv(0x60);
    let pubs = vec![
        cardanowall::sealed_poe::x25519_public_key(&r0)
            .unwrap()
            .to_vec(),
        cardanowall::sealed_poe::x25519_public_key(&r1)
            .unwrap()
            .to_vec(),
    ];
    ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext,
            recipient_public_keys: &pubs,
            hashes,
            skip_shuffle: true,
            ..Default::default()
        },
        &mut counter_rng(0xabcd_ef01),
    )
    .expect("wrap")
}

#[test]
fn low_order_epk_is_a_non_match_never_a_throw() {
    let hashes = test_hashes();
    for epk_hex in LOW_ORDER_EPKS {
        let low_order = hex::decode(epk_hex).unwrap();
        // Per-slot KEK uniqueness forbids two slots sharing the same epk, so the
        // two-slot all-low-order envelope pairs `low_order` with a DISTINCT
        // low-order point. Both still drive the X25519 shared secret to all-zero,
        // which is the property under test.
        let partner_hex = LOW_ORDER_EPKS
            .iter()
            .find(|&&e| e != *epk_hex)
            .expect("a distinct low-order epk is always available");
        let partner_low_order = hex::decode(partner_hex).unwrap();

        // All-low-order envelope: no slot can be accepted → clean non-match.
        let r0 = make_priv(0x11);
        let r1 = make_priv(0x55);
        let pubs = vec![
            cardanowall::sealed_poe::x25519_public_key(&r0)
                .unwrap()
                .to_vec(),
            cardanowall::sealed_poe::x25519_public_key(&r1)
                .unwrap()
                .to_vec(),
        ];
        let out = ecies_sealed_poe_wrap_with_rng(
            WrapArgs {
                plaintext: b"all-low-order",
                recipient_public_keys: &pubs,
                hashes: &hashes,
                skip_shuffle: true,
                ..Default::default()
            },
            &mut counter_rng(0x1234_5678),
        )
        .expect("wrap");
        let SealedSlots::X25519(slots) = &out.envelope.slots else {
            unreachable!()
        };
        let all_low: Vec<X25519Slot> = slots
            .iter()
            .enumerate()
            .map(|(i, s)| X25519Slot {
                epk: if i == 0 {
                    low_order.clone()
                } else {
                    partner_low_order.clone()
                },
                wrap: s.wrap.clone(),
            })
            .collect();
        let env = SealedEnvelope {
            slots: SealedSlots::X25519(all_low),
            ..out.envelope.clone()
        };
        let stranger = make_priv(0x99);
        let res = ecies_sealed_poe_unwrap(
            &env,
            &out.ciphertext,
            &hashes,
            UnwrapKeys::Single(&stranger),
            None,
        )
        .expect("must not error");
        assert!(!res.matched(), "{epk_hex}: all-low-order should not match");

        // Multi-priv form, all-low-order, still no match.
        let res = ecies_sealed_poe_unwrap(
            &env,
            &out.ciphertext,
            &hashes,
            UnwrapKeys::Multi(&[make_priv(0x99), make_priv(0xcd)]),
            None,
        )
        .expect("must not error");
        assert!(!res.matched(), "{epk_hex}: multi-priv all-low-order");

        // Trial-decrypt all-low-order → NoMatch.
        let res = ecies_sealed_poe_trial_decrypt(
            &env,
            &hashes,
            TrialDecryptKeys::Multi(&[make_priv(0x99)]),
            None,
        )
        .expect("must not error");
        assert_eq!(res, TrialDecryptResult::NoMatch, "{epk_hex}");

        // Legitimate slot 0 + low-order slot 1: slot 0 still wrap-opens, but
        // the clobbered slot set breaks the transcript so nothing is accepted
        // → TAMPERED_HEADER (not a crash, not WRONG_RECIPIENT_KEY).
        let out = wrap_two_recipients(b"low-order-epk-regression", &hashes);
        let SealedSlots::X25519(slots) = &out.envelope.slots else {
            unreachable!()
        };
        let clobbered: Vec<X25519Slot> = slots
            .iter()
            .enumerate()
            .map(|(i, s)| {
                if i == 1 {
                    X25519Slot {
                        epk: low_order.clone(),
                        wrap: s.wrap.clone(),
                    }
                } else {
                    s.clone()
                }
            })
            .collect();
        let env = SealedEnvelope {
            slots: SealedSlots::X25519(clobbered),
            ..out.envelope.clone()
        };
        let mut probe = UnwrapProbe::default();
        let res = ecies_sealed_poe_unwrap(
            &env,
            &out.ciphertext,
            &hashes,
            UnwrapKeys::Single(&make_priv(0x20)),
            Some(&mut probe),
        )
        .expect("must not error");
        assert_eq!(
            res,
            UnwrapResult::NotMatched {
                reason: UnwrapFailureReason::TamperedHeader
            },
            "{epk_hex}: clobbered sibling slot"
        );
        // Constant-time across slots: every slot entered even past the match.
        assert_eq!(probe.inner.count, env.slots.len(), "{epk_hex}");
    }
}

// --------------------------------------------------------------------------
// Bundle dispatch (in-test)
// --------------------------------------------------------------------------

#[test]
fn bundle_dispatch_classical_envelope() {
    let recipient_priv = fill(0x21, 32);
    let recipient_pub = cardanowall::sealed_poe::x25519_public_key(&recipient_priv).unwrap();
    let hashes = test_hashes();
    let sealed = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: b"bundle-dispatch-roundtrip",
            recipient_public_keys: &[recipient_pub.to_vec()],
            hashes: &hashes,
            cek: Some(&fill(0x33, 32)),
            nonce: Some(&fill(0x44, 24)),
            ephemeral_secrets: Some(&[fill(0x55, 32)]),
            skip_shuffle: true,
            ..Default::default()
        },
        &mut no_rng(),
    )
    .expect("wrap");

    // Unwraps from x25519_private_keys; a non-matching hybrid seed is ignored.
    let res = ecies_sealed_poe_unwrap(
        &sealed.envelope,
        &sealed.ciphertext,
        &hashes,
        UnwrapKeys::Bundle(&RecipientKeyBundle {
            x25519_private_keys: vec![recipient_priv.clone()],
            mlkem768x25519_secret_seeds: vec![fill(0xfe, 32)],
        }),
        None,
    )
    .expect("unwrap");
    assert_eq!(
        res,
        UnwrapResult::Matched {
            plaintext: b"bundle-dispatch-roundtrip".to_vec()
        }
    );

    // Bundle trial-decrypt == flat-list trial-decrypt, byte-for-byte.
    let flat = ecies_sealed_poe_trial_decrypt(
        &sealed.envelope,
        &hashes,
        TrialDecryptKeys::Multi(std::slice::from_ref(&recipient_priv)),
        None,
    )
    .expect("trial");
    let bundled = ecies_sealed_poe_trial_decrypt(
        &sealed.envelope,
        &hashes,
        TrialDecryptKeys::Bundle(&RecipientKeyBundle {
            x25519_private_keys: vec![recipient_priv.clone()],
            mlkem768x25519_secret_seeds: vec![],
        }),
        None,
    )
    .expect("trial");
    assert_eq!(flat, bundled);
    assert!(matches!(bundled, TrialDecryptResult::Match { .. }));

    // Empty x25519 list (archived-only identity) → clean non-match.
    let res = ecies_sealed_poe_unwrap(
        &sealed.envelope,
        &sealed.ciphertext,
        &hashes,
        UnwrapKeys::Bundle(&RecipientKeyBundle {
            x25519_private_keys: vec![],
            mlkem768x25519_secret_seeds: vec![fill(0x01, 32)],
        }),
        None,
    )
    .expect("unwrap");
    assert_eq!(
        res,
        UnwrapResult::NotMatched {
            reason: UnwrapFailureReason::WrongRecipientKey
        }
    );
    let trial = ecies_sealed_poe_trial_decrypt(
        &sealed.envelope,
        &hashes,
        TrialDecryptKeys::Bundle(&RecipientKeyBundle::default()),
        None,
    )
    .expect("trial");
    assert_eq!(trial, TrialDecryptResult::NoMatch);
}

#[test]
fn bundle_dispatch_hybrid_envelope() {
    let seed = fill(0x11, 32);
    let seed_arr: [u8; 32] = seed.clone().try_into().unwrap();
    let public_key = xwing_keygen(&seed_arr);
    let hashes = test_hashes();
    let sealed = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: b"bundle-dispatch-roundtrip",
            recipient_public_keys: &[public_key.to_vec()],
            hashes: &hashes,
            kem: Some(SealedKem::Mlkem768X25519),
            cek: Some(&fill(0xab, 32)),
            nonce: Some(&fill(0xcd, 24)),
            eseeds: Some(&[fill(0xe0, 64)]),
            skip_shuffle: true,
            ..Default::default()
        },
        &mut no_rng(),
    )
    .expect("wrap");

    // Unwraps from mlkem768x25519_secret_seeds; classical privs irrelevant.
    let res = ecies_sealed_poe_unwrap(
        &sealed.envelope,
        &sealed.ciphertext,
        &hashes,
        UnwrapKeys::Bundle(&RecipientKeyBundle {
            x25519_private_keys: vec![fill(0x99, 32)],
            mlkem768x25519_secret_seeds: vec![seed.clone()],
        }),
        None,
    )
    .expect("unwrap");
    assert_eq!(
        res,
        UnwrapResult::Matched {
            plaintext: b"bundle-dispatch-roundtrip".to_vec()
        }
    );

    // Empty hybrid seed list facing a hybrid record → NoMatch.
    let trial = ecies_sealed_poe_trial_decrypt(
        &sealed.envelope,
        &hashes,
        TrialDecryptKeys::Bundle(&RecipientKeyBundle {
            x25519_private_keys: vec![fill(0x21, 32)],
            mlkem768x25519_secret_seeds: vec![],
        }),
        None,
    )
    .expect("trial");
    assert_eq!(trial, TrialDecryptResult::NoMatch);
}

// --------------------------------------------------------------------------
// Hybrid slots_mac covers kem_ct (in-test)
// --------------------------------------------------------------------------

#[test]
fn hybrid_slots_mac_covers_kem_ct() {
    let seed_a = fill(0x11, 32);
    let seed_b = fill(0x22, 32);
    let pub_a = xwing_keygen(&seed_a.clone().try_into().unwrap());
    let pub_b = xwing_keygen(&seed_b.clone().try_into().unwrap());
    let hashes = test_hashes();

    let out = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: b"hybrid-slots-mac-kem-ct-coverage",
            recipient_public_keys: &[pub_a.to_vec(), pub_b.to_vec()],
            hashes: &hashes,
            kem: Some(SealedKem::Mlkem768X25519),
            cek: Some(&fill(0xab, 32)),
            nonce: Some(&fill(0xcd, 24)),
            eseeds: Some(&[fill(0xe1, 64), fill(0xe2, 64)]),
            skip_shuffle: true,
            ..Default::default()
        },
        &mut no_rng(),
    )
    .expect("wrap");

    // Sanity: recipient A opens cleanly before tampering.
    let clean = ecies_sealed_poe_unwrap(
        &out.envelope,
        &out.ciphertext,
        &hashes,
        UnwrapKeys::Single(&seed_a),
        None,
    )
    .expect("unwrap");
    assert!(clean.matched());

    // Flip a byte of slot 1's kem_ct; slot 0 (recipient A) untouched. Slot 0
    // still wrap-opens, but the transcript covers every slot's kem_ct, so its
    // MAC check fails → TAMPERED_HEADER.
    let SealedSlots::Mlkem768X25519(slots) = &out.envelope.slots else {
        unreachable!()
    };
    let mut tampered_ct = slots[1].kem_ct.clone();
    tampered_ct[0] ^= 0x01;
    let tampered = SealedEnvelope {
        slots: SealedSlots::Mlkem768X25519(vec![
            slots[0].clone(),
            Mlkem768X25519Slot {
                kem_ct: tampered_ct,
                wrap: slots[1].wrap.clone(),
            },
        ]),
        ..out.envelope.clone()
    };
    let res = ecies_sealed_poe_unwrap(
        &tampered,
        &out.ciphertext,
        &hashes,
        UnwrapKeys::Single(&seed_a),
        None,
    )
    .expect("unwrap");
    assert_eq!(
        res,
        UnwrapResult::NotMatched {
            reason: UnwrapFailureReason::TamperedHeader
        }
    );
}

#[test]
fn hybrid_kem_ct_length_mismatch_is_rejected_before_decap() {
    let seed = fill(0x31, 32);
    let public_key = xwing_keygen(&seed.clone().try_into().unwrap());
    let hashes = test_hashes();
    let out = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: b"",
            recipient_public_keys: &[public_key.to_vec()],
            hashes: &hashes,
            kem: Some(SealedKem::Mlkem768X25519),
            cek: Some(&fill(0xab, 32)),
            nonce: Some(&fill(0xcd, 24)),
            eseeds: Some(&[fill(0xe0, 64)]),
            skip_shuffle: true,
            ..Default::default()
        },
        &mut no_rng(),
    )
    .expect("wrap");

    let SealedSlots::Mlkem768X25519(slots) = &out.envelope.slots else {
        unreachable!()
    };
    let good = &slots[0];

    for bad_ct in [
        // Under-length: drop the last byte.
        good.kem_ct[..good.kem_ct.len() - 1].to_vec(),
        // Over-length: append a byte.
        {
            let mut ct = good.kem_ct.clone();
            ct.push(0u8);
            ct
        },
    ] {
        let tampered = SealedEnvelope {
            slots: SealedSlots::Mlkem768X25519(vec![Mlkem768X25519Slot {
                kem_ct: bad_ct,
                wrap: good.wrap.clone(),
            }]),
            ..out.envelope.clone()
        };
        let err = ecies_sealed_poe_unwrap(
            &tampered,
            &out.ciphertext,
            &hashes,
            UnwrapKeys::Single(&seed),
            None,
        )
        .expect_err("kem_ct length mismatch");
        assert_eq!(err.code(), "KEM_CT_LENGTH_MISMATCH");
    }
}

// --------------------------------------------------------------------------
// Production-path roundtrip + shuffle property (in-test)
// --------------------------------------------------------------------------

#[test]
fn production_roundtrip_every_recipient_with_shuffle() {
    let privs = [make_priv(0x11), make_priv(0x55), make_priv(0x99)];
    let pubs: Vec<Vec<u8>> = privs
        .iter()
        .map(|p| {
            cardanowall::sealed_poe::x25519_public_key(p)
                .unwrap()
                .to_vec()
        })
        .collect();
    let hashes = test_hashes();
    let plaintext = b"shuffle production path roundtrip";
    let out = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext,
            recipient_public_keys: &pubs,
            hashes: &hashes,
            ..Default::default()
        },
        &mut counter_rng(0x9999_1234),
    )
    .expect("wrap");
    for priv_key in &privs {
        let res = ecies_sealed_poe_unwrap(
            &out.envelope,
            &out.ciphertext,
            &hashes,
            UnwrapKeys::Single(priv_key),
            None,
        )
        .expect("unwrap");
        assert_eq!(
            res,
            UnwrapResult::Matched {
                plaintext: plaintext.to_vec()
            }
        );
    }
}

#[test]
fn shuffle_permutes_recipient_positions_across_runs() {
    let privs = [make_priv(0x11), make_priv(0x55), make_priv(0x99)];
    let pubs: Vec<Vec<u8>> = privs
        .iter()
        .map(|p| {
            cardanowall::sealed_poe::x25519_public_key(p)
                .unwrap()
                .to_vec()
        })
        .collect();
    let hashes = test_hashes();
    let mut rng = counter_rng(0xfeed_face_dead_beef);
    let mut orderings = std::collections::HashSet::new();
    for _ in 0..1000 {
        let out = ecies_sealed_poe_wrap_with_rng(
            WrapArgs {
                plaintext: b"shuffle-by-recipient-position",
                recipient_public_keys: &pubs,
                hashes: &hashes,
                ..Default::default()
            },
            &mut rng,
        )
        .expect("wrap");
        let positions = recipient_positions(&out, &privs, &hashes);
        orderings.insert(positions);
        if orderings.len() >= 4 {
            break;
        }
    }
    assert!(orderings.len() >= 2, "shuffle should permute slot order");
}

/// For each recipient priv, find the slot index it matches (test-only probe):
/// the full envelope is trial-decrypted, so the per-slot fold reports the
/// matched index directly.
fn recipient_positions(
    out: &SealedPoeOutput,
    privs: &[Vec<u8>],
    hashes: &BTreeMap<String, Vec<u8>>,
) -> Vec<i32> {
    privs
        .iter()
        .map(|priv_key| {
            let res = ecies_sealed_poe_trial_decrypt(
                &out.envelope,
                hashes,
                TrialDecryptKeys::Multi(std::slice::from_ref(priv_key)),
                None,
            )
            .expect("trial");
            match res {
                TrialDecryptResult::Match { slot_idx, .. } => slot_idx as i32,
                TrialDecryptResult::NoMatch => -1,
            }
        })
        .collect()
}
